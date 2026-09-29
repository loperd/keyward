//! An item's card: what is visible on the screen and what can be copied.
//!
//! Secrets do not come here. Only the visible fields go out, along with the
//! signs "there is a password" and "there is a TOTP" — the values themselves are
//! given on a request of their own and, by default, straight into the clipboard,
//! bypassing the interface.

use serde::{Deserialize, Serialize};

use crate::items::ItemKind;

/// What exactly is being asked to be copied or shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretField {
    Password,
    Username,
    /// The current one-time code, worked out of the stored secret.
    Totp,
    /// The stored secret itself — for the editor, which must show and keep
    /// the secret, never the code made of it.
    TotpSecret,
    CardNumber,
    CardCode,
    /// The name on the card: no secret, but autofill takes every value it
    /// types from the daemon, and it is typed along with the rest.
    CardHolder,
    /// The expiry in several shapes: paying for something, one place asks for
    /// `12/29`, another for `12/2029`, and a third for the month and the year in
    /// separate fields.
    CardExpShort,
    CardExpLong,
    CardExpMonth,
    CardExpYear,
    Notes,
    PrivateKey,
    /// A custom field by name: there can be many and they are named all
    /// manner of ways.
    Custom(String),
    /// A password the login had before, by its place in the history: 0 is
    /// the one replaced last. As secret as the password itself.
    PasswordHistory(usize),
}

impl SecretField {
    /// Whether the clipboard is worth clearing after a copy. Not for a login
    /// or an address: those are often pasted twice, and having them vanish is
    /// irritating.
    pub fn is_sensitive(&self) -> bool {
        // An expiry and a login are useless on their own, and when paying for
        // something they are pasted several times: wiping them from the
        // clipboard only gets in the way.
        !matches!(
            self,
            Self::Username
                | Self::CardHolder
                | Self::CardExpShort
                | Self::CardExpLong
                | Self::CardExpMonth
                | Self::CardExpYear
        )
    }
}

/// A visible field of a card.
/// An extra thing a field can copy: an expiry has four of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailAction {
    pub label: String,
    pub secret: SecretField,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailField {
    /// The key of a built-in field: "username", "password", "note". The
    /// translation is the interface's business: it has the person's language
    /// and the daemon does not.
    /// `None` means a person made the field's name up and there is nothing to
    /// translate.
    #[serde(default)]
    pub key: Option<String>,
    pub label: String,
    /// The value, when the field is not a secret.
    pub value: Option<String>,
    /// What the button copies.
    pub secret: Option<SecretField>,
    /// Hide the value behind dots until "show" is pressed.
    pub hidden: bool,
    /// Show it in a monospaced face: keys, numbers, fingerprints.
    pub mono: bool,
    /// The extra things it can copy.
    #[serde(default)]
    pub extra: Vec<DetailAction>,
}

/// An expiry in four shapes. The year arrives from the vault both as `29` and
/// as `2029`, and is brought to one shape so that what is copied is
/// predictable.
pub fn card_expiry(month: Option<&str>, year: Option<&str>) -> Option<(String, String)> {
    let m = month?.trim();
    let y = year?.trim();
    if m.is_empty() || y.is_empty() {
        return None;
    }
    let mm = if m.len() == 1 { format!("0{m}") } else { m.to_string() };
    let yyyy = match y.len() {
        2 => format!("20{y}"),
        _ => y.to_string(),
    };
    Some((mm, yyyy))
}

/// The last two digits of a year.
///
/// Cutting the string by bytes is not allowed: the year arrives from the vault
/// as whoever put it there wrote it, and one character outside ASCII in it was
/// enough to bring the whole process down — the index `len() - 2` landed in the
/// middle of a character, and a slice at such an index panics.
pub fn year_short(year: &str) -> String {
    let count = year.chars().count();
    year.chars().skip(count.saturating_sub(2)).collect()
}

/// A card number's mask: the first six digits and the last four. A card is
/// recognised by them at a glance, and cannot be charged with them — dots
/// instead of a number do not give that.
pub fn mask_card_number(number: &str) -> String {
    let digits: Vec<char> = number.chars().filter(|c| c.is_ascii_digit()).collect();
    match digits.len() {
        0 => String::new(),
        n if n <= 4 => digits.iter().collect(),
        n if n < 12 => format!("···· {}", digits[n - 4..].iter().collect::<String>()),
        n => format!(
            "{} ···· {}",
            digits[..6].iter().collect::<String>(),
            digits[n - 4..].iter().collect::<String>()
        ),
    }
}

/// A password the login had before, as far as it can be shown: when it was
/// replaced, never its value. The value comes on a request of its own, like
/// the password's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    /// Its place in the history, the one `SecretField::PasswordHistory` takes.
    pub index: usize,
    /// When it stopped being the password, RFC 3339.
    pub last_used: Option<String>,
}

/// An item's passkey, as far as it can be shown. There is no private key here
/// and there cannot be: it stays encrypted inside the item.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Passkey {
    /// The decrypted identifier: a passkey can be deleted by it.
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub key_algorithm: Option<String>,
    pub key_curve: Option<String>,
    /// Discoverable: a site can show it without knowing the login.
    pub discoverable: bool,
    pub counter: Option<u64>,
    /// When it was created, RFC 3339.
    pub created: Option<String>,
    /// When keyward last signed in with it, RFC 3339. Kept on this machine
    /// only, so a sign-in elsewhere does not show here.
    #[serde(default)]
    pub last_used: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemDetail {
    pub id: String,
    pub name: String,
    pub kind: ItemKind,
    pub folder_name: Option<String>,
    pub fields: Vec<DetailField>,
    pub uris: Vec<String>,
    /// A login's passkeys.
    #[serde(default)]
    pub passkeys: Vec<Passkey>,
    /// The passwords the login had before, newest first — dates only.
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    /// The item asks for the master password again before a secret is shown.
    pub reprompt: bool,
    /// A card's fields without the secret ones: the number and the code come
    /// back only on a request of their own, so that they do not settle in the
    /// interface's memory every time an item is opened.
    #[serde(default)]
    pub card: Option<crate::edits::CardEdit>,
    /// An identity's fields.
    #[serde(default)]
    pub identity: Option<crate::edits::IdentityEdit>,
    /// A favourite.
    #[serde(default)]
    pub favorite: bool,
    /// The custom fields in full, for editing. They reach the card's list
    /// separately and without the service `kw-*` ones, but all of them have to
    /// be editable: in Bitwarden they are visible and editable too.
    #[serde(default)]
    pub custom: Vec<CustomField>,
    /// The item lies in the trash: it has to be shown differently and its
    /// actions are different — bring it back or finish it off.
    #[serde(default)]
    pub deleted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_history_password_is_a_secret_of_its_own() {
        let field = SecretField::PasswordHistory(2);
        assert_eq!(serde_json::to_value(&field).unwrap(), serde_json::json!({ "password_history": 2 }));
        assert_eq!(serde_json::from_str::<SecretField>(r#"{"password_history":0}"#).unwrap(), SecretField::PasswordHistory(0));
        assert!(field.is_sensitive(), "the clipboard is cleared after it");
    }

    #[test]
    fn expiry_is_normalised_to_one_shape() {
        assert_eq!(card_expiry(Some("12"), Some("2029")), Some(("12".into(), "2029".into())));
        assert_eq!(card_expiry(Some("1"), Some("29")), Some(("01".into(), "2029".into())));
        assert_eq!(card_expiry(Some(" 3 "), Some(" 31 ")), Some(("03".into(), "2031".into())));
        assert_eq!(card_expiry(None, Some("2029")), None);
        assert_eq!(card_expiry(Some("12"), Some("")), None);
    }

    #[test]
    fn expiry_parts_do_not_wipe_the_clipboard() {
        for f in [SecretField::CardExpShort, SecretField::CardExpLong, SecretField::CardExpMonth, SecretField::CardExpYear] {
            assert!(!f.is_sensitive(), "{f:?} must not wipe the clipboard");
        }
        assert!(SecretField::CardNumber.is_sensitive());
    }

    #[test]
    fn card_mask_keeps_bin_and_last_four() {
        assert_eq!(mask_card_number("5168 7554 1234 8897"), "516875 ···· 8897");
        assert_eq!(mask_card_number("4111111111111111"), "411111 ···· 1111");
    }

    #[test]
    fn short_numbers_do_not_leak_more_than_they_should() {
        // Under twelve digits there is no BIN to show and no point showing
        // one.
        assert_eq!(mask_card_number("12345678"), "···· 5678");
        assert_eq!(mask_card_number("123"), "123");
        assert_eq!(mask_card_number(""), "");
    }

    #[test]
    fn username_is_not_wiped_from_clipboard() {
        assert!(!SecretField::Username.is_sensitive());
        assert!(SecretField::Password.is_sensitive());
        assert!(SecretField::Totp.is_sensitive());
        assert!(SecretField::TotpSecret.is_sensitive());
        // The editor asks for the secret under this name; the code under
        // "totp". Mixing them up saved a code over the secret.
        assert_eq!(serde_json::to_string(&SecretField::TotpSecret).unwrap(), "\"totp_secret\"");
        assert_eq!(serde_json::to_string(&SecretField::Totp).unwrap(), "\"totp\"");
        assert!(SecretField::Custom("api-key".into()).is_sensitive());
    }

    #[test]
    fn a_year_that_is_not_digits_does_not_bring_the_process_down() {
        // A year in the vault is an ordinary string, and what lies in it is
        // not the client's decision. A `[len-2..]` slice by bytes landed in the
        // middle of a character and panicked: one card with an emoji in its
        // expiry took the daemon down together with the ssh agent, and in an
        // organisation any of its admins can create such a card.
        assert_eq!(year_short("2029"), "29");
        assert_eq!(year_short("29"), "29");
        assert_eq!(year_short("9"), "9");
        assert_eq!(year_short(""), "");
        assert_eq!(year_short("🎉"), "🎉");
        assert_eq!(year_short("éa"), "éa");
        assert_eq!(year_short("20🎉"), "0🎉");
        assert_eq!(year_short("two thousand and twenty-nine"), "ne");
    }

    #[test]
    fn rubbish_in_an_expiry_passes_without_a_panic() {
        // We do not undertake to weed out a non-numeric expiry; what matters
        // is only that the whole path of "decrypted, shown, copied" does not
        // fall over on it.
        let (mm, yyyy) = card_expiry(Some("🙂"), Some("🎉")).expect("not thrown away");
        assert_eq!((mm.as_str(), year_short(&yyyy).as_str()), ("🙂", "🎉"));
    }
}


/// A custom field of an item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    /// `None` means the field is hidden and its value is shown only on
    /// demand.
    pub value: Option<String>,
    pub hidden: bool,
    /// A linked field's target: without it the link cannot be restored on an
    /// edit.
    #[serde(default)]
    pub linked_id: Option<u32>,
    /// The kind in Bitwarden's terms: 0 text, 1 hidden, 2 checkbox, 3
    /// linked.
    #[serde(default)]
    pub kind: u8,
}
