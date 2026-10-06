//! Reading the vault out of our own sync snapshot.
//!
//! Everything used to be read from the `rbw` database, which loses deleted
//! items, favourites, organisation names and collections. Here is the same
//! parsing but over our own model — which is why the trash and organisations
//! finally exist.
//!
//! The values in a snapshot are encrypted; decryption uses the keys the vault
//! holds in memory.

use std::collections::HashMap;

use keyward_bw::model::{Cipher, Sync};
use keyward_core::detail::{
    card_expiry, mask_card_number, year_short, DetailAction, DetailField, ItemDetail, SecretField,
};
use keyward_core::items::{Catalog, CollectionView, ItemKind, Org, OrgRights, VaultItem};
use keyward_core::source::VaultEntry;
use rbw::locked::Keys;

/// The IIN is enough to recognise a network. This runs inside the vault
/// process, so the catalogue never needs a card number or even its prefix.
fn card_network(number: &str) -> Option<&'static str> {
    let digits: String = number.chars().filter(char::is_ascii_digit).collect();
    let first4 = digits.get(..4).and_then(|v| v.parse::<u16>().ok());
    if digits.starts_with('4') {
        Some("Visa")
    } else if matches!(digits.get(..2), Some("51" | "52" | "53" | "54" | "55"))
        || first4.is_some_and(|n| (2221..=2720).contains(&n))
    {
        Some("Mastercard")
    } else if matches!(digits.get(..2), Some("34" | "37")) {
        Some("American Express")
    } else if digits.starts_with("6011")
        || digits.starts_with("65")
        || matches!(
            digits.get(..3),
            Some("644" | "645" | "646" | "647" | "648" | "649")
        )
    {
        Some("Discover")
    } else if digits.starts_with("2131") || digits.starts_with("1800") || digits.starts_with("35") {
        Some("JCB")
    } else if matches!(digits.get(..2), Some("30" | "36" | "38")) {
        Some("Diners Club")
    } else if digits.starts_with("62") {
        Some("UnionPay")
    } else {
        None
    }
}

/// The keys the vault is decrypted with.
pub struct Ring<'a> {
    pub user: &'a Keys,
    pub orgs: &'a HashMap<String, Keys>,
}

impl Ring<'_> {
    pub(crate) fn base(&self, org_id: Option<&str>) -> Option<&Keys> {
        match org_id {
            Some(id) => self.orgs.get(id),
            None => Some(self.user),
        }
    }

    /// The item's own key, if it has one: Bitwarden encrypts the fields of
    /// such an item with this rather than with the user key.
    pub(crate) fn item(&self, cipher: &Cipher) -> Option<Keys> {
        let base = self.base(cipher.organization_id.as_deref())?;
        let raw = cipher.key.as_deref()?;
        if !authenticated(raw) {
            tracing::warn!(entry = %cipher.id, "the item key has no mac and was not taken");
            return None;
        }
        let opened = rbw::cipherstring::CipherString::new(raw)
            .ok()?
            .decrypt_locked_symmetric(base)
            .ok()?;
        // An item key is 32 bytes of encryption and 32 of mac. Any shorter
        // and `Keys::enc_key()` walks past the end of the buffer and takes the
        // daemon down. A server that answers like that is lying: we check.
        if opened.data().len() < 64 {
            tracing::warn!(entry = %cipher.id, "the item key is shorter than 64 bytes and was not taken");
            return None;
        }
        Some(Keys::new(opened))
    }
}

/// Decrypt a value with one particular item's keys.
pub fn decrypt_for(ring: &Ring<'_>, cipher: &Cipher, value: &str) -> Option<String> {
    let keys = ring.base(cipher.organization_id.as_deref())?;
    let item = ring.item(cipher);
    decrypt(value, keys, item.as_ref())
}

/// Encrypt a value the way that same item will read it: if the item has a key
/// of its own, the user key must not be used or the item becomes
/// unreadable.
pub fn encrypt_for(ring: &Ring<'_>, cipher: &Cipher, text: &str) -> anyhow::Result<String> {
    encrypt_bytes_for(ring, cipher, text.as_bytes())
}

/// [`encrypt_for`] over bytes: a secret held in locked memory is sealed
/// without first being copied into a string.
pub fn encrypt_bytes_for(ring: &Ring<'_>, cipher: &Cipher, text: &[u8]) -> anyhow::Result<String> {
    let base = ring
        .base(cipher.organization_id.as_deref())
        .ok_or_else(|| keyward_core::fault!("err.noOrgKey"))?;
    // If the item has a key of its own that could not be opened, the user key
    // must not be used: the official client would read the field with the item
    // key and get rubbish. A refusal beats quiet corruption.
    let item = ring.item(cipher);
    if item.is_none() && cipher.key.is_some() {
        return Err(keyward_core::fault!("err.itemKeyLocked"));
    }
    let key = item.as_ref().unwrap_or(base);
    Ok(
        rbw::cipherstring::CipherString::encrypt_symmetric(key, text)
            .map_err(|e| keyward_core::fault!("err.encryptValue", "reason" => e))?
            .to_string(),
    )
}

/// The value of an item's custom field, by name.
pub fn field_of(ring: &Ring<'_>, cipher: &Cipher, name: &str) -> Option<String> {
    let keys = ring.base(cipher.organization_id.as_deref())?;
    let item = ring.item(cipher);
    field(cipher, keys, item.as_ref(), name)
}

pub(crate) fn decrypt(value: &str, keys: &Keys, item: Option<&Keys>) -> Option<String> {
    // Without a mac we do not decrypt at all -- see `authenticated`.
    if !authenticated(value) {
        tracing::warn!("a value with no mac; not decrypting");
        return None;
    }
    let raw = rbw::cipherstring::CipherString::new(value)
        .ok()?
        .decrypt_symmetric(keys, item)
        .ok()?;
    String::from_utf8(raw).ok()
}

/// Does the value carry a mac?
///
/// Bitwarden writes symmetric values as `2.iv|ct|mac`. The `rbw` library also
/// accepts the shortened `2.iv|ct`: then `mac` inside is `None` and the check
/// is **silently skipped** — decryption goes through unauthenticated.
///
/// For us that is a hole, not a concession. The server -- or whoever swapped
/// the snapshot on disk -- can cut the mac off and get two gifts at once. The
/// first is a padding oracle: `decrypt` returns an `Option`, so from outside
/// it is visible whether text came out, and one bit per request recovers the
/// plaintext with no key at all. The second is editing through the IV: in CBC
/// the first block of plaintext can be changed at will, and fields here are
/// looked up **by their decrypted name**, so somebody else's field turns into
/// `kw-host` (the item becomes an ssh route) or into `kw-vault-addr` (a
/// connection to Vault appears).
///
/// So exactly three parts are required and nothing but type two: the obsolete
/// type zero carries no mac by definition.
pub(crate) fn authenticated(value: &str) -> bool {
    let Some(body) = value.strip_prefix("2.") else {
        return false;
    };
    body.split('|').count() == 3
}

/// The kind of item, from the protocol's number.
fn kind_of(cipher: &Cipher) -> ItemKind {
    match cipher.kind {
        3 => ItemKind::Card,
        4 => ItemKind::Identity,
        5 => ItemKind::SshKey,
        2 => ItemKind::SecureNote,
        _ if cipher.card.is_some() => ItemKind::Card,
        _ if cipher.identity.is_some() => ItemKind::Identity,
        _ if cipher.ssh_key.is_some() => ItemKind::SshKey,
        _ if cipher.login.is_some() => ItemKind::Login,
        _ => ItemKind::SecureNote,
    }
}

/// The value of a custom field, by name.
/// The marker field: the item is a service one and stays out of the list.
/// Encrypting an arbitrary string with the user key.
///
/// Tied to no item: used for what lives next to the vault rather than inside
/// it, such as the generator's history.
pub fn encrypt_blob(ring: &Ring<'_>, text: &str) -> anyhow::Result<String> {
    Ok(
        rbw::cipherstring::CipherString::encrypt_symmetric(ring.user, text.as_bytes())
            .map_err(|e| keyward_core::fault!("err.encryptValue", "reason" => e))?
            .to_string(),
    )
}

/// Decrypting into bytes, for what is not text: private keys, for instance.
pub fn decrypt_raw(ring: &Ring<'_>, value: &str) -> Option<Vec<u8>> {
    if !authenticated(value) {
        tracing::warn!("a value with no mac; not decrypting");
        return None;
    }
    rbw::cipherstring::CipherString::new(value)
        .ok()?
        .decrypt_symmetric(ring.user, None)
        .ok()
}

/// Encrypting with an organisation's key, for what every member of it has to
/// read: the names of collections, for instance.
pub fn encrypt_with_org(ring: &Ring<'_>, org_id: &str, text: &str) -> anyhow::Result<String> {
    let keys = ring
        .orgs
        .get(org_id)
        .ok_or_else(|| keyward_core::fault!("err.noOrgKeySync"))?;
    Ok(
        rbw::cipherstring::CipherString::encrypt_symmetric(keys, text.as_bytes())
            .map_err(|e| keyward_core::fault!("err.encryptValue", "reason" => e))?
            .to_string(),
    )
}

/// An organisation's raw key, needed to hand it to a new member.
pub fn org_key_bytes(ring: &Ring<'_>, org_id: &str) -> Option<Vec<u8>> {
    let keys = ring.orgs.get(org_id)?;
    let mut raw = keys.enc_key().to_vec();
    raw.extend_from_slice(keys.mac_key());
    Some(raw)
}

pub fn decrypt_blob(ring: &Ring<'_>, value: &str) -> Option<String> {
    decrypt(value, ring.user, None)
}

pub const HIDDEN_MARK: &str = "kw-hidden";
/// The Vault address inside the hidden item that holds the root token. The
/// name differs from `kw-vault-addr` on purpose: otherwise the hidden item
/// would stand in for the connection itself.
pub const ROOT_ADDR: &str = "kw-root-addr";

/// Every `kw-*` field of an item, by its full name. What any of them means is
/// the business of the plugin that asked for it; here they are only read off
/// and carried.
fn own_fields(
    cipher: &Cipher,
    keys: &Keys,
    item: Option<&Keys>,
) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for f in &cipher.fields {
        let Some(name) = f.name.as_deref().and_then(|n| decrypt(n, keys, item)) else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if !name.starts_with(keyward_core::source::FIELD_PREFIX) {
            continue;
        }
        let value = f
            .value
            .as_deref()
            .and_then(|v| decrypt(v, keys, item))
            .unwrap_or_default();
        out.insert(name, value);
    }
    out
}

fn field(cipher: &Cipher, keys: &Keys, item: Option<&Keys>, name: &str) -> Option<String> {
    cipher
        .fields
        .iter()
        .find(|f| {
            f.name
                .as_deref()
                .and_then(|n| decrypt(n, keys, item))
                .is_some_and(|n| n.trim().eq_ignore_ascii_case(name))
        })
        .and_then(|f| f.value.as_deref())
        .and_then(|v| decrypt(v, keys, item))
}

/// The catalogue for the interface.
pub fn catalog(snapshot: &Sync, ring: &Ring<'_>) -> Catalog {
    let mut items = Vec::new();
    // Reused passwords are found by salted hashes kept here and nowhere else:
    // the salt is new for every build of the catalogue, so a hash is of no
    // use outside it, and neither it nor the password reaches the window.
    let salt: [u8; 32] = rand::random();
    let mut password_hashes: Vec<(usize, [u8; 32])> = Vec::new();

    let folders: Vec<(String, String)> = snapshot
        .folders
        .iter()
        .map(|f| {
            (
                f.id.clone(),
                decrypt(&f.name, ring.user, None).unwrap_or_else(|| f.name.clone()),
            )
        })
        .collect();

    let orgs: Vec<Org> = snapshot
        .profile
        .organizations
        .iter()
        .map(|o| {
            let rights = org_rights(o);
            Org {
                id: o.id.clone(),
                // An organisation's name arrives in the clear: in the web
                // interface it is common to every member too.
                name: o.name.clone(),
                role: rights.role,
                can: rights.view(),
                count: 0,
            }
        })
        .collect();

    let collections: Vec<CollectionView> = snapshot
        .collections
        .iter()
        .map(|c| {
            let keys = ring.base(c.organization_id.as_deref());
            CollectionView {
                id: c.id.clone(),
                name: keys
                    .and_then(|k| decrypt(&c.name, k, None))
                    .unwrap_or_else(|| c.name.clone()),
                org_id: c.organization_id.clone(),
                read_only: c.read_only,
                count: 0,
            }
        })
        .collect();

    let org_names: HashMap<&str, &str> = snapshot
        .profile
        .organizations
        .iter()
        .map(|o| (o.id.as_str(), o.name.as_str()))
        .collect();

    for cipher in &snapshot.ciphers {
        let Some(keys) = ring.base(cipher.organization_id.as_deref()) else {
            continue;
        };
        let item_key = ring.item(cipher);
        let ik = item_key.as_ref();
        let dec = |v: &str| decrypt(v, keys, ik);

        // keyward's own service items stay out of the list.
        if field(cipher, keys, ik, HIDDEN_MARK).is_some() {
            continue;
        }

        let kind = kind_of(cipher);
        // A brand marker is enough for a recognisable card row. The PAN stays
        // inside this process and is never part of the GUI catalogue.
        let card_brand = if kind == ItemKind::Card {
            cipher.card.as_ref().and_then(|c| {
                c.brand
                    .as_deref()
                    .and_then(dec)
                    .filter(|b| !b.trim().is_empty() && !b.eq_ignore_ascii_case("other"))
                    .or_else(|| {
                        c.number
                            .as_deref()
                            .and_then(dec)
                            .and_then(|n| card_network(&n).map(str::to_string))
                    })
            })
        } else {
            None
        };
        let subtitle = match kind {
            ItemKind::Login => cipher
                .login
                .as_ref()
                .and_then(|l| l.username.as_deref())
                .and_then(dec),
            ItemKind::Card => cipher.card.as_ref().and_then(|c| {
                let last4 = c.number.as_deref().and_then(dec).map(|n| {
                    let digits: Vec<char> = n.chars().filter(char::is_ascii_digit).collect();
                    digits.iter().rev().take(4).rev().collect::<String>()
                });
                match (c.brand.as_deref().and_then(dec), last4) {
                    (Some(b), Some(l)) => Some(format!("{b} ····{l}")),
                    (b, l) => b.or(l),
                }
            }),
            ItemKind::Identity => cipher
                .identity
                .as_ref()
                .and_then(|i| i.email.as_deref().or(i.username.as_deref()))
                .and_then(dec),
            ItemKind::SshKey => cipher
                .ssh_key
                .as_ref()
                .and_then(|k| k.fingerprint.as_deref())
                .and_then(dec),
            ItemKind::SecureNote => None,
        };

        if !cipher.in_trash() {
            if let Some(password) = cipher.login.as_ref().and_then(|l| l.password.as_deref()).and_then(dec).map(zeroize::Zeroizing::new) {
                if !password.is_empty() {
                    use sha2::Digest as _;
                    let mut h = sha2::Sha256::new();
                    h.update(salt);
                    h.update(password.as_bytes());
                    password_hashes.push((items.len(), h.finalize().into()));
                }
            }
        }
        let expires = cipher.card.as_ref().and_then(|c| {
            let month: u32 = c.exp_month.as_deref().and_then(dec)?.trim().parse().ok()?;
            let year: u32 = c.exp_year.as_deref().and_then(dec)?.trim().parse().ok()?;
            let year = if year < 100 { 2000 + year } else { year };
            (1..=12).contains(&month).then(|| format!("{year:04}-{month:02}"))
        });

        items.push(VaultItem {
            id: cipher.id.clone(),
            name: dec(&cipher.name)
                .unwrap_or_else(|| keyward_core::text::t("item.nameUndecrypted", &[])),
            kind,
            subtitle,
            card_brand,
            folder_id: cipher.folder_id.clone(),
            folder_name: cipher
                .folder_id
                .as_deref()
                .and_then(|id| folders.iter().find(|(fid, _)| fid == id))
                .map(|(_, name)| name.clone()),
            org_id: cipher.organization_id.clone(),
            uris: cipher
                .login
                .as_ref()
                .map(|l| {
                    l.uris
                        .iter()
                        .filter_map(|u| u.uri.as_deref())
                        .filter_map(dec)
                        .collect()
                })
                .unwrap_or_default(),
            // What the fields mean is a plugin's business; the list shows them
            // because a person put them there and looks for items by them.
            tags: own_fields(cipher, keys, ik),
            has_totp: cipher.login.as_ref().is_some_and(|l| l.totp.is_some()),
            passkeys: cipher
                .login
                .as_ref()
                .and_then(|l| l.fido2_credentials.as_ref())
                .and_then(|v| v.as_array())
                .map(|a| a.len() as u32)
                .unwrap_or(0),
            favorite: cipher.favorite,
            deleted: cipher.in_trash(),
            org_name: cipher
                .organization_id
                .as_deref()
                .and_then(|id| org_names.get(id))
                .map(|n| (*n).to_string()),
            collection_ids: cipher.collection_ids.clone(),
            reprompt: cipher.reprompt != 0,
            revised: cipher.revision_date.clone(),
            password_revised: cipher.login.as_ref().and_then(|l| l.password_revision_date.clone()),
            expires,
            reused: 0,
            reuse_group: None,
        });
    }

    // Each login learns how many others share its password, and the shared
    // ones get one group number between them.
    let mut groups: Vec<[u8; 32]> = Vec::new();
    for (index, hash) in &password_hashes {
        let same = password_hashes.iter().filter(|(_, h)| h == hash).count() as u32;
        items[*index].reused = same.saturating_sub(1);
        if same > 1 {
            let group = match groups.iter().position(|g| g == hash) {
                Some(g) => g,
                None => {
                    groups.push(*hash);
                    groups.len() - 1
                }
            };
            items[*index].reuse_group = Some(group as u32);
        }
    }

    items.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Catalog::build(items, &folders, &orgs, &collections)
}

/// The items a plugin may work with: the vault's ssh keys and everything
/// carrying keyward's own `kw-*` fields. The trash is left out: a key from a
/// deleted item must not sign anything.
pub fn plugin_entries(snapshot: &Sync, ring: &Ring<'_>) -> Vec<VaultEntry> {
    let mut out = Vec::new();
    for cipher in &snapshot.ciphers {
        if cipher.in_trash() {
            continue;
        }
        let Some(keys) = ring.base(cipher.organization_id.as_deref()) else {
            continue;
        };
        let item_key = ring.item(cipher);
        let ik = item_key.as_ref();
        let dec = |v: &str| decrypt(v, keys, ik);

        // An ssh key with no fields on it is an entry too: the ssh plugin shows
        // those as "not bound yet", and skipping them here would hide half the
        // work its section is opened for.
        let fields = own_fields(cipher, keys, ik);
        let ssh = cipher.ssh_key.as_ref();
        if ssh.is_none() && fields.is_empty() {
            continue;
        }

        out.push(VaultEntry {
            id: cipher.id.clone(),
            name: dec(&cipher.name).unwrap_or_default(),
            fields,
            public_key: ssh.and_then(|k| k.public_key.as_deref()).and_then(dec),
            private_key: ssh.and_then(|k| k.private_key.as_deref()).and_then(dec),
        });
    }
    out
}

/// A login's passkeys: every field is an encrypted string of its own, except
/// the date. The private key (`keyValue`) is not decrypted at all.
pub(crate) fn passkeys(
    login: &keyward_bw::model::Login,
    dec: &dyn Fn(&str) -> Option<String>,
) -> Vec<keyward_core::detail::Passkey> {
    let Some(serde_json::Value::Array(list)) = login.fido2_credentials.as_ref() else {
        return Vec::new();
    };
    let field = |c: &serde_json::Value, k: &str| {
        c.get(k)
            .and_then(|v| v.as_str())
            .and_then(|v| dec(v))
            .filter(|v| !v.is_empty())
    };
    list.iter()
        .map(|c| keyward_core::detail::Passkey {
            credential_id: field(c, "credentialId").unwrap_or_default(),
            rp_id: field(c, "rpId").unwrap_or_default(),
            rp_name: field(c, "rpName"),
            user_name: field(c, "userName"),
            user_display_name: field(c, "userDisplayName"),
            key_algorithm: field(c, "keyAlgorithm"),
            key_curve: field(c, "keyCurve"),
            discoverable: field(c, "discoverable").is_some_and(|v| v == "true"),
            counter: field(c, "counter").and_then(|v| v.parse().ok()),
            created: c
                .get("creationDate")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            last_used: None,
        })
        .collect()
}

/// The passwords a login had before, as the card shows them: the date only.
/// The value is not decrypted here at all — it comes on a request of its own.
pub(crate) fn password_history(cipher: &Cipher) -> Vec<keyward_core::detail::PasswordHistoryEntry> {
    let Some(list) = cipher.password_history.as_ref().and_then(|h| h.as_array()) else { return Vec::new() };
    list.iter()
        .enumerate()
        .filter(|(_, e)| e.get("password").and_then(|p| p.as_str()).is_some_and(|p| !p.is_empty()))
        .map(|(index, e)| keyward_core::detail::PasswordHistoryEntry {
            index,
            last_used: e.get("lastUsedDate").and_then(|d| d.as_str()).map(str::to_string),
        })
        .collect()
}

/// An item's card.
pub fn detail(snapshot: &Sync, ring: &Ring<'_>, id: &str) -> Option<ItemDetail> {
    let cipher = snapshot.ciphers.iter().find(|c| c.id == id)?;
    let keys = ring.base(cipher.organization_id.as_deref())?;
    let item_key = ring.item(cipher);
    let ik = item_key.as_ref();
    let dec = |v: &str| decrypt(v, keys, ik);

    let mut fields: Vec<DetailField> = Vec::new();
    let mut uris = Vec::new();

    // A key instead of a translation: the daemon used to give Russian
    // captions, and an English interface stood a Russian "Login" next to
    // "Addresses".
    // It also does away with comparing captions by string in the edit form.
    let visible = |key: &str, value: Option<String>, mono: bool| -> Option<DetailField> {
        let v = value.filter(|v| !v.trim().is_empty())?;
        Some(DetailField {
            key: Some(key.into()),
            label: key.into(),
            value: Some(v),
            secret: None,
            hidden: false,
            mono,
            extra: Vec::new(),
        })
    };
    let secret = |key: &str, f: SecretField, mono: bool| DetailField {
        key: Some(key.into()),
        label: key.into(),
        value: None,
        secret: Some(f),
        hidden: true,
        mono,
        extra: Vec::new(),
    };

    let kind = kind_of(cipher);
    match kind {
        ItemKind::Login => {
            if let Some(login) = &cipher.login {
                uris = login
                    .uris
                    .iter()
                    .filter_map(|u| u.uri.as_deref())
                    .filter_map(dec)
                    .collect();
                if let Some(name) = login.username.as_deref().and_then(dec) {
                    fields.push(DetailField {
                        key: Some("username".into()),
                        label: "username".into(),
                        value: Some(name),
                        secret: Some(SecretField::Username),
                        hidden: false,
                        mono: false,
                        extra: Vec::new(),
                    });
                }
                if login.password.is_some() {
                    fields.push(secret("password", SecretField::Password, true));
                }
                if login.totp.is_some() {
                    fields.push(secret("totp", SecretField::Totp, true));
                }
            }
        }
        ItemKind::Card => {
            if let Some(card) = &cipher.card {
                fields.extend(visible(
                    "cardholder",
                    card.cardholder_name.as_deref().and_then(dec),
                    false,
                ));
                fields.extend(visible("brand", card.brand.as_deref().and_then(dec), false));
                let m = card.exp_month.as_deref().and_then(dec);
                let y = card.exp_year.as_deref().and_then(dec);
                if let Some((mm, yyyy)) = card_expiry(m.as_deref(), y.as_deref()) {
                    let yy = year_short(&yyyy);
                    fields.push(DetailField {
                        key: Some("expiry".into()),
                        label: "expiry".into(),
                        value: Some(format!("{mm}/{yyyy}")),
                        secret: Some(SecretField::CardExpLong),
                        hidden: false,
                        mono: true,
                        extra: vec![
                            DetailAction {
                                label: format!("{mm}/{yy}"),
                                secret: SecretField::CardExpShort,
                            },
                            DetailAction {
                                label: mm.clone(),
                                secret: SecretField::CardExpMonth,
                            },
                            DetailAction {
                                label: yyyy.clone(),
                                secret: SecretField::CardExpYear,
                            },
                        ],
                    });
                }
                if let Some(raw) = card.number.as_deref().and_then(dec) {
                    fields.push(DetailField {
                        key: Some("cardNumber".into()),
                        label: "cardNumber".into(),
                        value: Some(mask_card_number(&raw)),
                        secret: Some(SecretField::CardNumber),
                        hidden: true,
                        mono: true,
                        extra: Vec::new(),
                    });
                }
                if card.code.is_some() {
                    fields.push(secret("cardCode", SecretField::CardCode, true));
                }
            }
        }
        ItemKind::Identity => {
            if let Some(i) = &cipher.identity {
                let full = match (
                    i.first_name.as_deref().and_then(dec),
                    i.last_name.as_deref().and_then(dec),
                ) {
                    (Some(f), Some(l)) => Some(format!("{f} {l}")),
                    (f, l) => f.or(l),
                };
                fields.extend(visible("fullName", full, false));
                fields.extend(visible("email", i.email.as_deref().and_then(dec), false));
                fields.extend(visible("phone", i.phone.as_deref().and_then(dec), false));
            }
        }
        ItemKind::SshKey => {
            if let Some(k) = &cipher.ssh_key {
                fields.extend(visible(
                    "fingerprint",
                    k.fingerprint.as_deref().and_then(dec),
                    true,
                ));
                fields.extend(visible(
                    "publicKey",
                    k.public_key.as_deref().and_then(dec),
                    true,
                ));
                if k.private_key.is_some() {
                    fields.push(secret("privateKey", SecretField::PrivateKey, true));
                }
                // Hosts are shown not by a field but by the editor in the
                // card, where they can be both seen and changed.
            }
        }
        ItemKind::SecureNote => {}
    }

    for f in &cipher.fields {
        let Some(name) = f.name.as_deref().and_then(dec) else {
            continue;
        };
        if name.trim().to_lowercase().starts_with("kw-") {
            continue;
        }
        let hidden = f.kind == 1;

        // A checkbox and a linked field are not secrets: copying "yes" is
        // pointless, and a linked field has no value of its own at all, only a
        // reference to a field of the item. Linked fields used to disappear
        // from the card altogether: the check for an empty value threw them out
        // along with the rubbish.
        match f.kind {
            2 => {
                let yes = f
                    .value
                    .as_deref()
                    .and_then(dec)
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
                fields.push(DetailField {
                    key: Some("checkbox".into()),
                    label: name,
                    value: Some(if yes { "true".into() } else { "false".into() }),
                    secret: None,
                    hidden: false,
                    mono: false,
                    extra: Vec::new(),
                });
                continue;
            }
            3 => {
                fields.push(DetailField {
                    key: f.linked_id.map(|id| format!("link:{id}")),
                    label: name,
                    value: Some(format!("→ {}", linked_name(f.linked_id))),
                    secret: None,
                    hidden: false,
                    mono: false,
                    extra: Vec::new(),
                });
                continue;
            }
            _ => {}
        }

        let plain = f
            .value
            .as_deref()
            .and_then(dec)
            .filter(|v| !v.trim().is_empty());
        if !hidden && plain.is_none() {
            continue;
        }
        fields.push(DetailField {
            key: None,
            label: name.clone(),
            value: if hidden { None } else { plain },
            secret: Some(SecretField::Custom(name)),
            hidden,
            mono: hidden,
            extra: Vec::new(),
        });
    }

    if cipher.notes.is_some() {
        fields.push(DetailField {
            key: Some("note".into()),
            label: "note".into(),
            value: cipher.notes.as_deref().and_then(dec),
            secret: Some(SecretField::Notes),
            hidden: false,
            mono: false,
            extra: Vec::new(),
        });
    }

    // Editing needs every field, service ones included: they are visible in
    // the official client too, and hiding them from editing locks a person
    // out.
    let custom: Vec<keyward_core::detail::CustomField> = cipher
        .fields
        .iter()
        .filter_map(|f| {
            let name = f.name.as_deref().and_then(dec)?;
            let hidden = f.kind == 1;
            Some(keyward_core::detail::CustomField {
                value: if hidden {
                    None
                } else {
                    f.value.as_deref().and_then(dec)
                },
                name,
                hidden,
                kind: f.kind,
                linked_id: f.linked_id,
            })
        })
        .collect();

    // The sets of fields for editing, without the card number and the
    // verification code: the interface asks for those separately, when a person
    // actually opens them.
    let card_edit = cipher.card.as_ref().map(|c| keyward_core::edits::CardEdit {
        cardholder_name: c.cardholder_name.as_deref().and_then(dec),
        brand: c.brand.as_deref().and_then(dec),
        exp_month: c.exp_month.as_deref().and_then(dec),
        exp_year: c.exp_year.as_deref().and_then(dec),
        number: None,
        code: None,
    });
    let identity_edit = cipher
        .identity
        .as_ref()
        .map(|i| keyward_core::edits::IdentityEdit {
            title: i.title.as_deref().and_then(dec),
            first_name: i.first_name.as_deref().and_then(dec),
            middle_name: i.middle_name.as_deref().and_then(dec),
            last_name: i.last_name.as_deref().and_then(dec),
            username: i.username.as_deref().and_then(dec),
            company: i.company.as_deref().and_then(dec),
            email: i.email.as_deref().and_then(dec),
            phone: i.phone.as_deref().and_then(dec),
            address1: i.address1.as_deref().and_then(dec),
            address2: i.address2.as_deref().and_then(dec),
            address3: i.address3.as_deref().and_then(dec),
            city: i.city.as_deref().and_then(dec),
            state: i.state.as_deref().and_then(dec),
            postal_code: i.postal_code.as_deref().and_then(dec),
            country: i.country.as_deref().and_then(dec),
            ssn: i.ssn.as_deref().and_then(dec).map(Into::into),
            passport_number: i.passport_number.as_deref().and_then(dec).map(Into::into),
            license_number: i.license_number.as_deref().and_then(dec).map(Into::into),
        });

    Some(ItemDetail {
        id: cipher.id.clone(),
        name: dec(&cipher.name)
            .unwrap_or_else(|| keyward_core::text::t("item.nameUndecrypted", &[])),
        kind,
        folder_name: cipher.folder_id.as_deref().and_then(|fid| {
            snapshot
                .folders
                .iter()
                .find(|f| f.id == fid)
                .and_then(|f| decrypt(&f.name, ring.user, None))
        }),
        fields,
        custom,
        card: card_edit,
        identity: identity_edit,
        favorite: cipher.favorite,
        uris,
        passkeys: cipher
            .login
            .as_ref()
            .map(|l| passkeys(l, &dec))
            .unwrap_or_default(),
        password_history: password_history(cipher),
        deleted: cipher.in_trash(),
        reprompt: cipher.reprompt != 0,
    })
}

/// The name of the field a linked field points at.
///
/// The numbers are the official client's: they travel to the server as
/// `linkedId`, and a numbering of our own would make the item unreadable to
/// every other client.
///
/// The words come out of the shared dictionary, the same one the window reads.
/// A number we do not know is shown as it is: a field we did not understand
/// still has to be visible.
fn linked_name(id: Option<u32>) -> String {
    const KNOWN: &[u32] = &[
        100, 101, 300, 301, 302, 303, 304, 305, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409,
        410, 411, 412, 413, 414, 415, 416, 417, 418,
    ];
    let Some(id) = id else {
        return keyward_core::text::t("linked.none", &[]);
    };
    if !KNOWN.contains(&id) {
        return format!("#{id}");
    }
    keyward_core::text::t(&format!("linked.{id}"), &[])
}

#[cfg(test)]
mod signal_tests {
    use super::*;

    fn keys() -> Keys {
        let mut v = rbw::locked::Vec::new();
        v.extend((0..64u8).map(|i| i.wrapping_mul(37).wrapping_add(11)));
        Keys::new(v)
    }

    /// A login, a card: the catalogue reads their signals — a password two
    /// items share, a card's expiry, the dates — without the window ever
    /// seeing a password.
    #[test]
    fn shared_passwords_and_expiry_are_read_in_the_daemon() {
        let user = keys();
        let orgs = HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let enc = |t: &str| encrypt_blob(&ring, t).unwrap();
        let login = |id: &str, pw: &str| serde_json::json!({
            "id": id, "type": 1, "name": enc(id), "revisionDate": "2026-09-01T10:00:00Z",
            "login": { "username": enc("u"), "password": enc(pw), "passwordRevisionDate": "2024-01-01T00:00:00Z" }
        });
        let snapshot: Sync = serde_json::from_value(serde_json::json!({
            "profile": { "id": "me", "email": "a@b" },
            "folders": [], "collections": [],
            "ciphers": [
                login("a", "same-secret"),
                login("b", "same-secret"),
                login("c", "own-secret"),
                { "id": "d", "type": 3, "name": enc("card"), "card": { "expMonth": enc("9"), "expYear": enc("29") } }
            ]
        })).unwrap();
        let c = catalog(&snapshot, &ring);
        let by = |id: &str| c.items.iter().find(|i| i.id == id).unwrap();
        assert_eq!((by("a").reused, by("b").reused, by("c").reused), (1, 1, 0));
        assert_eq!(by("a").reuse_group, by("b").reuse_group);
        assert!(by("a").reuse_group.is_some() && by("c").reuse_group.is_none());
        assert_eq!(by("d").expires.as_deref(), Some("2029-09"));
        assert_eq!(by("a").revised.as_deref(), Some("2026-09-01T10:00:00Z"));
        assert_eq!(by("a").password_revised.as_deref(), Some("2024-01-01T00:00:00Z"));
        // Nothing of a password in what the window is given.
        let wire = serde_json::to_string(&c).unwrap();
        assert!(!wire.contains("same-secret") && !wire.contains("own-secret"));
    }
}

#[cfg(test)]
mod tests {
    use super::authenticated;

    #[test]
    fn a_value_with_no_mac_is_refused() {
        // Exactly the shape rbw accepts and on which it skips the mac check.
        assert!(!authenticated("2.aXY=|Y3Q="));
        assert!(authenticated("2.aXY=|Y3Q=|bWFj"));
    }

    #[test]
    fn other_types_are_refused() {
        // 0 is CBC with no mac, 1 has none either, 4 and 6 are RSA; none of
        // them belong on the symmetric path.
        for value in [
            "0.aXY=|Y3Q=",
            "1.aXY=|Y3Q=|bWFj",
            "4.Y3Q=",
            "6.Y3Q=|bWFj",
            "",
            "rubbish",
        ] {
            assert!(!authenticated(value), "accepted: {value}");
        }
    }

    #[test]
    fn extra_parts_are_refused() {
        assert!(!authenticated("2.aXY=|Y3Q=|bWFj|more"));
    }
}

/// One's rights in an organisation, from what the server sent with it.
pub fn org_rights(o: &keyward_bw::model::Organization) -> OrgRights {
    OrgRights {
        role: keyward_core::items::OrgRole::from_code(i32::from(o.kind)),
        permissions: keyward_core::items::OrgPermissions {
            manage_users: o.permissions.manage_users,
            create_new_collections: o.permissions.create_new_collections,
            edit_any_collection: o.permissions.edit_any_collection,
            delete_any_collection: o.permissions.delete_any_collection,
        },
    }
}
