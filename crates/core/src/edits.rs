//! Edits to items, and the queue that sends them.
//!
//! An edit is applied locally first and only then goes to the server. If the
//! server is down the edit is not lost: it waits in the queue with an
//! **encrypted** payload — exactly the ciphertext that would have gone to the
//! server. Keeping values in the clear on disk is not allowed: it would make
//! the vault worthless.
//!
//! The previous payload is kept alongside the new one, so that an edit can be
//! not only pushed again but rolled back.

use serde::{Deserialize, Serialize};

use crate::proto::Secret;

/// What became of an edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EditState {
    /// Waiting to be sent: the server did not answer, or answered with an
    /// error.
    Pending { attempts: u32, last_error: Option<String> },
    /// Sent and confirmed by the server.
    Pushed,
    /// Rolled back: the former value went back to the server.
    RolledBack,
}

/// One changed field, for showing to a person and nothing else. There are no
/// values here, or a secret would leak into the queue's file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedField {
    pub label: String,
    /// Was the field filled in before the edit?
    pub had_value: bool,
    /// Is it filled in after?
    pub has_value: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEdit {
    pub id: String,
    pub account_id: String,
    pub entry_id: String,
    /// The item's name. On disk it is sealed with the account's key; here it
    /// is empty while that vault is locked.
    pub entry_name: String,
    pub created_at: String,
    pub changed: Vec<ChangedField>,
    pub state: EditState,
    /// The edit belongs to an account whose vault is locked: its name, its
    /// fields and its dates are sealed with that account's key and cannot be
    /// read until it is opened.
    #[serde(default)]
    pub locked: bool,
    /// The edit's file is there but cannot be read or opened with its own
    /// account's key: it is shown so that it does not vanish quietly, and
    /// the only thing to do with it is to discard it.
    #[serde(default)]
    pub damaged: bool,
}

impl PendingEdit {
    pub fn is_waiting(&self) -> bool {
        matches!(self.state, EditState::Pending { .. })
    }

    /// Whether it is worth trying to send again by ourselves. After several
    /// failures we stop pulling at the server: if it answers with an error
    /// rather than silence, repeating will not cure it.
    pub fn retry_automatically(&self) -> bool {
        matches!(self.state, EditState::Pending { attempts, .. } if attempts < 5)
    }
}

/// "Left alone" and "take it away" are different things, and one field
/// expresses both: the outer `None` says nothing, the inner one clears. Serde
/// does not do this by itself.
pub mod double_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, T>(value: &Option<Option<T>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        match value {
            Some(inner) => inner.serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        Ok(Some(Option::deserialize(d)?))
    }
}

/// What a person changed in an item. `None` means the field was left alone,
/// `Some("")` that it was cleared: different intentions, and they must not be
/// muddled.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ItemEdit {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<Secret>,
    #[serde(default)]
    pub totp: Option<Secret>,
    #[serde(default)]
    pub notes: Option<Secret>,
    /// The site addresses. `None` leaves them alone, `Some` replaces them
    /// whole: a half-edit of the list breeds duplicates that get sorted out by
    /// hand later.
    #[serde(default)]
    pub uris: Option<Vec<String>>,
    /// The custom fields. One that exists under the same name is replaced, a
    /// new one is added.
    #[serde(default)]
    pub custom: Vec<CustomEdit>,
    /// The custom fields to take away.
    #[serde(default)]
    pub remove_custom: Vec<String>,
    /// The passkeys to delete, by their decrypted credentialId.
    #[serde(default)]
    pub remove_passkeys: Vec<String>,
    /// Forget the passwords the login had before.
    #[serde(default)]
    pub clear_password_history: bool,
    /// A favourite or not. `None` leaves it alone.
    #[serde(default)]
    pub favorite: Option<bool>,
    /// Which folder the item lies in. `None` leaves it alone, `Some(None)`
    /// takes it out of its folder. Moving an item from the edit form was not
    /// possible at all: the folder was set only at creation.
    #[serde(default, with = "crate::edits::double_option")]
    pub folder_id: Option<Option<String>>,
    /// The card's fields. `None` leaves them alone.
    #[serde(default)]
    pub card: Option<CardEdit>,
    /// The identity's fields. `None` leaves them alone.
    #[serde(default)]
    pub identity: Option<IdentityEdit>,
    /// Ask for the master password before showing this item's secrets.
    #[serde(default)]
    pub reprompt: Option<bool>,
    /// A new key for an ssh key item: made here or pasted in. `None` leaves
    /// the key alone. The public key and the fingerprint are never taken from
    /// the interface — they are derived from the private key.
    #[serde(default)]
    pub ssh_key: Option<SshKeyEdit>,
    /// Passkeys brought over from records merged into this one, already
    /// sealed with this item's key. Only the daemon fills it in: a window
    /// has no keys to seal a passkey with, and none comes over the wire.
    #[serde(skip)]
    pub add_passkeys: Vec<serde_json::Value>,
}

/// Which kind of key to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAlgorithm {
    Ed25519,
    Rsa4096,
}

/// Where an ssh key item's new key comes from.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum SshKeyEdit {
    /// Made by the daemon: the private key never passes through the window.
    Generate { algorithm: SshAlgorithm },
    /// Pasted in by a person. A passphrase, if the key is under one, is used
    /// once to open it and is not stored.
    Import {
        private_key: Secret,
        #[serde(default)]
        passphrase: Option<Secret>,
    },
    /// A draft the daemon holds — made or read there — named by its number.
    Draft { id: String },
}

/// Where a draft of an ssh key comes from. The daemon makes it or reads it;
/// the window never holds the private half.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum SshDraftSource {
    /// Made in the daemon.
    Generate { algorithm: SshAlgorithm },
    /// Read off the clipboard by the daemon itself.
    Clipboard {
        #[serde(default)]
        passphrase: Option<Secret>,
    },
    /// Typed or pasted into the form: it passes the window once, on its way
    /// here, and the form lets go of it.
    Paste {
        private_key: Secret,
        #[serde(default)]
        passphrase: Option<Secret>,
    },
    /// The key an item holds now, read in the daemon: its public half and
    /// fingerprint worked out again, for an item whose stored ones no longer
    /// match it.
    Stored { entry_id: String },
}

impl std::fmt::Debug for SshDraftSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generate { algorithm } => write!(f, "Generate({algorithm:?})"),
            Self::Clipboard { .. } => write!(f, "Clipboard"),
            Self::Paste { .. } => write!(f, "Paste(..)"),
            Self::Stored { entry_id } => write!(f, "Stored({entry_id})"),
        }
    }
}

/// A draft as the window sees it: its number and the public half.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshDraftView {
    pub id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub algorithm: String,
}

/// By hand, so that a pasted private key cannot reach a log through an
/// edit's `Debug`.
impl std::fmt::Debug for SshKeyEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generate { algorithm } => write!(f, "Generate({algorithm:?})"),
            Self::Import { .. } => write!(f, "Import(..)"),
            Self::Draft { id } => write!(f, "Draft({id})"),
        }
    }
}

/// By hand: an edit carries passwords, codes and hidden fields, and `Debug`
/// is what reaches a log. Only which fields changed is shown.
impl std::fmt::Debug for ItemEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ItemEdit({:?})", self.labels())
    }
}

impl std::fmt::Debug for CustomEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CustomEdit({:?}, kind {})", self.name, self.kind)
    }
}

impl std::fmt::Debug for CardEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CardEdit(..)")
    }
}

impl std::fmt::Debug for IdentityEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IdentityEdit(..)")
    }
}

impl ItemEdit {
    pub fn is_empty(&self) -> bool {
        if !self.remove_passkeys.is_empty() || !self.add_passkeys.is_empty() || self.clear_password_history {
            return false;
        }
        self.name.is_none()
            && self.username.is_none()
            && self.password.is_none()
            && self.totp.is_none()
            && self.notes.is_none()
            && self.uris.is_none()
            && self.custom.is_empty()
            && self.remove_custom.is_empty()
            && self.reprompt.is_none()
            && self.favorite.is_none()
            && self.folder_id.is_none()
            && self.card.is_none()
            && self.identity.is_none()
            && self.ssh_key.is_none()
    }

    /// The captions of the changed fields, for the list of edits. They are
    /// dictionary keys: the window writes the words.
    pub fn labels(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.name.is_some() { out.push("field.name".to_string()); }
        if self.username.is_some() { out.push("field.username".to_string()); }
        if self.password.is_some() { out.push("field.password".to_string()); }
        if self.totp.is_some() { out.push("field.totp".to_string()); }
        if self.notes.is_some() { out.push("field.note".to_string()); }
        if self.ssh_key.is_some() { out.push("field.privateKey".to_string()); }
        if self.clear_password_history { out.push("field.passwordHistory".to_string()); }
        if !self.add_passkeys.is_empty() { out.push("field.passkeys".to_string()); }
        out.extend(self.custom.iter().map(|f| f.name.clone()));
        out
    }
}

/// An edit's identifier: sixteen random bytes. It is the edit's file name
/// too, and the old one — the time plus the start of the item's id — told
/// anyone looking at the directory when which item was edited.
pub fn edit_id() -> String {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("the system's source of randomness");
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(state: EditState) -> PendingEdit {
        PendingEdit {
            id: "1".into(),
            account_id: "a".into(),
            entry_id: "e".into(),
            entry_name: "an item".into(),
            created_at: "2026-08-31T00:00:00Z".into(),
            changed: vec![ChangedField { label: "field.password".into(), had_value: true, has_value: true }],
            state,
            locked: false,
            damaged: false,
        }
    }

    #[test]
    fn only_pending_edits_are_waiting() {
        assert!(edit(EditState::Pending { attempts: 0, last_error: None }).is_waiting());
        assert!(!edit(EditState::Pushed).is_waiting());
        assert!(!edit(EditState::RolledBack).is_waiting());
    }

    #[test]
    fn automatic_retries_stop_after_a_few_attempts() {
        assert!(edit(EditState::Pending { attempts: 4, last_error: None }).retry_automatically());
        // A fifth failure means the server answers with an error rather than
        // keeping silent: from there let a person decide.
        assert!(!edit(EditState::Pending { attempts: 5, last_error: None }).retry_automatically());
        assert!(!edit(EditState::Pushed).retry_automatically());
    }

    #[test]
    fn untouched_edit_is_empty_but_cleared_field_is_not() {
        assert!(ItemEdit::default().is_empty());
        // Clearing a field is an edit too, and it has to reach the server.
        let cleared = ItemEdit { password: Some(Secret::default()), ..Default::default() };
        assert!(!cleared.is_empty());
        assert_eq!(cleared.labels(), vec!["field.password".to_string()]);
        // Moving an item between folders, or out of one, is an edit too.
        assert!(!ItemEdit { folder_id: Some(None), ..Default::default() }.is_empty());
        assert!(!ItemEdit { folder_id: Some(Some("f".into())), ..Default::default() }.is_empty());
    }

    #[test]
    fn a_pasted_key_does_not_reach_a_log() {
        let key = SshKeyEdit::Import {
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----".to_string().into(),
            passphrase: Some("hunter2".to_string().into()),
        };
        let edit = ItemEdit { ssh_key: Some(key), ..Default::default() };
        let shown = format!("{edit:?}");
        assert!(!shown.contains("BEGIN") && !shown.contains("hunter2"), "{shown}");
        // Nor a password, a code, a card number or a hidden field.
        let other = ItemEdit {
            password: Some("hunter2".to_string().into()),
            totp: Some("JBSWY3DPEHPK3PXP".to_string().into()),
            custom: vec![CustomEdit { name: "PIN".into(), value: "0000-secret".to_string().into(), kind: 1, linked_id: None }],
            card: Some(CardEdit { number: Some("4111111111111111".to_string().into()), ..Default::default() }),
            ..Default::default()
        };
        let shown = format!("{other:?}");
        for value in ["hunter2", "JBSWY3DP", "0000-secret", "4111"] {
            assert!(!shown.contains(value), "{value} in {shown}");
        }
        assert!(!edit.is_empty());
        assert_eq!(edit.labels(), vec!["field.privateKey".to_string()]);
        let generate: SshKeyEdit =
            serde_json::from_str(r#"{"source":"generate","algorithm":"rsa4096"}"#).unwrap();
        assert!(matches!(generate, SshKeyEdit::Generate { algorithm: SshAlgorithm::Rsa4096 }));
    }

    #[test]
    fn an_identifier_says_nothing_about_the_edit() {
        let id = edit_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(id, edit_id());
    }
}


/// A custom field inside an edit.
#[derive(Clone, Serialize, Deserialize)]
pub struct CustomEdit {
    pub name: String,
    pub value: Secret,
    /// The field's kind in Bitwarden's terms: 0 text, 1 hidden, 2 checkbox,
    /// 3 linked.
    #[serde(default)]
    pub kind: u8,
    /// Which field of the item a linked field points at. The numbers are the
    /// official client's: 100 the login, 101 the password, 3xx the card, 4xx
    /// the identity. It means anything only when `kind == 3`.
    #[serde(default)]
    pub linked_id: Option<u32>,
}


/// A bank card's fields. An empty string means "clear it", `None` means "leave
/// it alone": different intentions, and they must not be muddled.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardEdit {
    #[serde(default)]
    pub cardholder_name: Option<String>,
    #[serde(default)]
    pub number: Option<Secret>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub exp_month: Option<String>,
    #[serde(default)]
    pub exp_year: Option<String>,
    #[serde(default)]
    pub code: Option<Secret>,
}

/// An identity's fields. There are eighteen of them, and every one is needed
/// at some point when filling in somebody else's form.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityEdit {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub address1: Option<String>,
    #[serde(default)]
    pub address2: Option<String>,
    #[serde(default)]
    pub address3: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub ssn: Option<Secret>,
    #[serde(default)]
    pub passport_number: Option<Secret>,
    #[serde(default)]
    pub license_number: Option<Secret>,
}
