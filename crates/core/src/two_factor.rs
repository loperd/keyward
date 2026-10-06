//! The second factor. There are several providers and they behave
//! differently: one has the code in an app, another has to be asked to send it
//! by email, a third wants a button pressed on a piece of hardware. The
//! interface is obliged to tell them apart.

use serde::{Deserialize, Serialize};

/// What a person does to get the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwoFactorKind {
    /// The code comes from an authenticator app.
    Code,
    /// The code has to be asked for by email first.
    EmailCode,
    /// A physical key: plug it in and press.
    HardwareKey,
    /// Not a second factor: Bitwarden's check of a device it has not seen,
    /// a code it mails on its own when the password is right.
    NewDevice,
    /// A known provider that keyward cannot do.
    Unsupported,
}

/// The id the device check goes by among the second factors. Not one of
/// Bitwarden's: theirs stop at 7, and the check travels the same road — a
/// code, a step, the password kept in the daemon meanwhile.
pub const NEW_DEVICE: u8 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoFactorProvider {
    /// The numeric provider identifier in Bitwarden's protocol.
    pub id: u8,
    /// A name for the list to choose from. It is a fallback: the interface
    /// looks the id up in its own dictionary first.
    pub name: String,
    /// The hint under the input field.
    pub prompt: String,
    pub kind: TwoFactorKind,
}

impl TwoFactorProvider {
    /// A description of the provider from its number in Bitwarden's protocol.
    pub fn from_id(id: u8) -> Self {
        let (name, prompt, kind) = match id {
            0 => (
                "Authenticator app",
                "The six-digit code from the app",
                TwoFactorKind::Code,
            ),
            1 => (
                "Code by email",
                "The code from the letter",
                TwoFactorKind::EmailCode,
            ),
            2 => ("Duo", "Duo is not supported", TwoFactorKind::Unsupported),
            3 => (
                "YubiKey",
                "Plug the key in and press the button; the code types itself",
                TwoFactorKind::HardwareKey,
            ),
            4 => ("U2F", "U2F is not supported", TwoFactorKind::Unsupported),
            5 => ("Remembered device", "", TwoFactorKind::Unsupported),
            6 => ("Organisation Duo", "Duo is not supported", TwoFactorKind::Unsupported),
            7 => ("WebAuthn", "WebAuthn is not supported", TwoFactorKind::Unsupported),
            NEW_DEVICE => ("New device", "The code from the letter about a new device", TwoFactorKind::NewDevice),
            _ => ("Unknown method", "keyward cannot do this method", TwoFactorKind::Unsupported),
        };
        Self { id, name: name.to_string(), prompt: prompt.to_string(), kind }
    }

    pub fn is_supported(&self) -> bool {
        self.kind != TwoFactorKind::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_and_email_are_supported() {
        assert_eq!(TwoFactorProvider::from_id(0).kind, TwoFactorKind::Code);
        assert_eq!(TwoFactorProvider::from_id(1).kind, TwoFactorKind::EmailCode);
        assert!(TwoFactorProvider::from_id(3).is_supported(), "a YubiKey gives an ordinary code");
    }

    #[test]
    fn webauthn_and_duo_are_honestly_marked_unsupported() {
        // Silently showing an input field where typing decides nothing is
        // worse than saying plainly that the method is not supported.
        for id in [2u8, 4, 6, 7] {
            assert!(!TwoFactorProvider::from_id(id).is_supported(), "id {id} must be unsupported");
        }
    }

    #[test]
    fn unknown_id_does_not_panic() {
        assert!(!TwoFactorProvider::from_id(99).is_supported());
    }
}
