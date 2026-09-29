//! The state of the vault. It lives in the core rather than in
//! `keyward-vault` because the GUI shows it and the CLI prints it, and neither
//! of them should have to depend on the cryptographic layer.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VaultState {
    /// Neither the server address nor the email has been set.
    NeedsSetup,
    /// Configured, but not logged in.
    LoggedOut { email: String, server: String },
    /// Logged in; no keys in memory.
    Locked { email: String, server: String },
    /// Keys in memory; entries decrypt.
    Unlocked { email: String, server: String, entries: usize, tagged: usize },
    /// The source is a file; the vault takes no part.
    Disabled,
}

impl VaultState {
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Self::Unlocked { .. })
    }

    /// A short caption for the CLI.
    pub fn summary(&self) -> String {
        match self {
            Self::NeedsSetup => "not set up".into(),
            Self::LoggedOut { email, server } => format!("logged out ({email} @ {server})"),
            Self::Locked { email, server } => format!("locked ({email} @ {server})"),
            Self::Unlocked { entries, tagged, .. } => {
                format!("unlocked: {entries} entries, {tagged} of them a plugin's to work with")
            }
            Self::Disabled => "off (the source is a file)".into(),
        }
    }
}
