//! Our own model of the `/api/sync` answer, not `rbw`'s.
//!
//! The reason is specific: `rbw` throws away what a client is incomplete
//! without — deleted items (so there is no trash), favourites, organisation
//! names and collections. Parsing the answer ourselves costs less than working
//! around those losses.
//!
//! The values here stay **encrypted**: decryption is a layer of its own.

use serde::{Deserialize, Deserializer, Serialize};

/// A `null` where a value belongs is not an error but an everyday thing: the
/// server sends one both where a list is expected and where a flag is.
/// `#[serde(default)]` does not save us here — it fires only on a missing
/// field, not on an explicit `null`, and the whole parse fell over because of a
/// single `"uris": null`.
pub(crate) fn null_as_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// A list in which one crooked item does not take the whole vault with it.
///
/// Parsing goes element by element: what did not parse is dropped with a
/// warning and the rest stays. Otherwise one `"type": "1"` in one item was
/// enough for the whole of `/api/sync` not to parse, and the client quietly
/// went on living on a stale snapshot: no new items, no deleted ones. A `null`,
/// or something that is not a list at all where a list belongs, is not an error
/// either but emptiness.
pub(crate) fn lenient_vec<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let raw = match serde_json::Value::deserialize(d)? {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Null => return Ok(Vec::new()),
        other => {
            tracing::warn!(got = %kind_name(&other), "something that is not a list arrived where a list belongs; taking it as empty");
            return Ok(Vec::new());
        }
    };
    let mut out = Vec::with_capacity(raw.len());
    for value in raw {
        match serde_json::from_value(value) {
            Ok(item) => out.push(item),
            Err(e) => tracing::warn!(error = %e, "an item from the server's answer was dropped: it will not parse"),
        }
    }
    Ok(out)
}

fn kind_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "a list",
        serde_json::Value::Object(_) => "an object",
    }
}

/// The sync answer in full.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sync {
    #[serde(default, alias = "Profile", deserialize_with = "null_as_default")]
    pub profile: Profile,
    #[serde(default, alias = "Folders", deserialize_with = "lenient_vec")]
    pub folders: Vec<Folder>,
    #[serde(default, alias = "Collections", deserialize_with = "lenient_vec")]
    pub collections: Vec<Collection>,
    #[serde(default, alias = "Ciphers", deserialize_with = "lenient_vec")]
    pub ciphers: Vec<Cipher>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(default, alias = "Id", deserialize_with = "null_as_default")]
    pub id: String,
    #[serde(default, alias = "Email", deserialize_with = "null_as_default")]
    pub email: String,
    #[serde(default, alias = "Name")]
    pub name: Option<String>,
    #[serde(default, alias = "Key")]
    pub key: Option<String>,
    #[serde(default, alias = "PrivateKey")]
    pub private_key: Option<String>,
    /// Organisations together with their **names**: those are what `rbw`
    /// loses.
    #[serde(default, alias = "Organizations", deserialize_with = "lenient_vec")]
    pub organizations: Vec<Organization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(default, alias = "Name", deserialize_with = "null_as_default")]
    pub name: String,
    #[serde(default, alias = "Key")]
    pub key: Option<String>,
    #[serde(default, alias = "Enabled", deserialize_with = "null_as_default")]
    pub enabled: bool,
    /// The access level: 0 owner, 1 admin, 2 user, 3 manager.
    #[serde(rename = "type", alias = "Type", default, deserialize_with = "null_as_default")]
    pub kind: u8,
    #[serde(default, alias = "Status", deserialize_with = "null_as_default")]
    pub status: i8,
    /// What a custom role may do. Absent or null for the fixed roles.
    #[serde(default, alias = "Permissions", deserialize_with = "null_as_default")]
    pub permissions: OrgPermissions,
}

/// The server's `permissions` of one's membership; only what keyward acts on.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgPermissions {
    #[serde(default, alias = "ManageUsers", deserialize_with = "null_as_default")]
    pub manage_users: bool,
    #[serde(default, alias = "CreateNewCollections", deserialize_with = "null_as_default")]
    pub create_new_collections: bool,
    #[serde(default, alias = "EditAnyCollection", deserialize_with = "null_as_default")]
    pub edit_any_collection: bool,
    #[serde(default, alias = "DeleteAnyCollection", deserialize_with = "null_as_default")]
    pub delete_any_collection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(default, alias = "Name", deserialize_with = "null_as_default")]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(default, alias = "Name", deserialize_with = "null_as_default")]
    pub name: String,
    #[serde(default, alias = "OrganizationId")]
    pub organization_id: Option<String>,
    #[serde(default, alias = "ReadOnly", deserialize_with = "null_as_default")]
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    #[serde(alias = "Id")]
    pub id: String,
    #[serde(rename = "type", alias = "Type", default, deserialize_with = "null_as_default")]
    pub kind: u8,
    #[serde(default, alias = "Name", deserialize_with = "null_as_default")]
    pub name: String,
    #[serde(default, alias = "Notes")]
    pub notes: Option<String>,
    #[serde(default, alias = "FolderId")]
    pub folder_id: Option<String>,
    #[serde(default, alias = "OrganizationId")]
    pub organization_id: Option<String>,
    #[serde(default, alias = "CollectionIds", deserialize_with = "lenient_vec")]
    pub collection_ids: Vec<String>,
    /// The item's own key, if it has one.
    #[serde(default, alias = "Key")]
    pub key: Option<String>,
    #[serde(default, alias = "Favorite", deserialize_with = "null_as_default")]
    pub favorite: bool,
    /// Ask for the master password again.
    #[serde(default, alias = "Reprompt", deserialize_with = "null_as_default")]
    pub reprompt: u8,
    /// Filled in means the item is in the trash. This is exactly what `rbw`
    /// throws away.
    #[serde(default, alias = "DeletedDate")]
    pub deleted_date: Option<String>,
    #[serde(default, alias = "RevisionDate")]
    pub revision_date: Option<String>,
    /// The creation date, needed by the export that repeats Bitwarden's
    /// format.
    #[serde(default, alias = "CreationDate")]
    pub creation_date: Option<String>,
    /// Password history. We neither show it nor understand it, but on a write
    /// the server replaces the item whole: not sending it back means erasing
    /// every former password of a person with one edit of a name.
    #[serde(default, alias = "PasswordHistory")]
    pub password_history: Option<serde_json::Value>,
    #[serde(default, alias = "Fields", deserialize_with = "lenient_vec")]
    pub fields: Vec<Field>,
    #[serde(default, alias = "Login")]
    pub login: Option<Login>,
    #[serde(default, alias = "Card")]
    pub card: Option<Card>,
    #[serde(default, alias = "Identity")]
    pub identity: Option<Identity>,
    #[serde(default, alias = "SecureNote")]
    pub secure_note: Option<serde_json::Value>,
    #[serde(default, alias = "SshKey")]
    pub ssh_key: Option<SshKey>,
}

impl Cipher {
    /// An empty string is not a date: a server that sent `"deletedDate": ""`
    /// would otherwise sweep the whole vault into the trash at a stroke.
    pub fn in_trash(&self) -> bool {
        self.deleted_date.as_deref().is_some_and(|d| !d.trim().is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    #[serde(rename = "type", alias = "Type", default, deserialize_with = "null_as_default")]
    pub kind: u8,
    #[serde(default, alias = "Name")]
    pub name: Option<String>,
    #[serde(default, alias = "Value")]
    pub value: Option<String>,
    #[serde(default, alias = "LinkedId")]
    pub linked_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    #[serde(default, alias = "Username")]
    pub username: Option<String>,
    #[serde(default, alias = "Password")]
    pub password: Option<String>,
    #[serde(default, alias = "Totp")]
    pub totp: Option<String>,
    #[serde(default, alias = "Uris", deserialize_with = "lenient_vec")]
    pub uris: Vec<Uri>,
    /// Passkey credentials. We neither show nor touch them, but we are obliged
    /// to send them back as they are: on a write the server replaces the whole
    /// login part, and a lost passkey is a lost way in, with nothing to restore
    /// it from.
    #[serde(default, alias = "Fido2Credentials")]
    pub fido2_credentials: Option<serde_json::Value>,
    #[serde(default, alias = "PasswordRevisionDate")]
    pub password_revision_date: Option<String>,
    #[serde(default, alias = "AutofillOnPageLoad")]
    pub autofill_on_page_load: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Uri {
    #[serde(default, alias = "Uri")]
    pub uri: Option<String>,
    #[serde(default, alias = "Match")]
    pub match_type: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    #[serde(default, alias = "CardholderName")]
    pub cardholder_name: Option<String>,
    #[serde(default, alias = "Number")]
    pub number: Option<String>,
    #[serde(default, alias = "Brand")]
    pub brand: Option<String>,
    #[serde(default, alias = "ExpMonth")]
    pub exp_month: Option<String>,
    #[serde(default, alias = "ExpYear")]
    pub exp_year: Option<String>,
    #[serde(default, alias = "Code")]
    pub code: Option<String>,
}

/// An identity in full, not only what the card shows.
///
/// We show three fields out of this, but are obliged to keep them all: when an
/// item changes, the server replaces its contents with what we sent, and a
/// field we did not parse disappears for a person for ever. The address, the
/// company and the passport number used to vanish on a rename.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    #[serde(default, alias = "Title")]
    pub title: Option<String>,
    #[serde(default, alias = "FirstName")]
    pub first_name: Option<String>,
    #[serde(default, alias = "MiddleName")]
    pub middle_name: Option<String>,
    #[serde(default, alias = "LastName")]
    pub last_name: Option<String>,
    #[serde(default, alias = "Email")]
    pub email: Option<String>,
    #[serde(default, alias = "Phone")]
    pub phone: Option<String>,
    #[serde(default, alias = "Username")]
    pub username: Option<String>,
    #[serde(default, alias = "Address1")]
    pub address1: Option<String>,
    #[serde(default, alias = "Address2")]
    pub address2: Option<String>,
    #[serde(default, alias = "Address3")]
    pub address3: Option<String>,
    #[serde(default, alias = "City")]
    pub city: Option<String>,
    #[serde(default, alias = "State")]
    pub state: Option<String>,
    #[serde(default, alias = "PostalCode")]
    pub postal_code: Option<String>,
    #[serde(default, alias = "Country")]
    pub country: Option<String>,
    #[serde(default, alias = "Company")]
    pub company: Option<String>,
    #[serde(default, alias = "Ssn")]
    pub ssn: Option<String>,
    #[serde(default, alias = "PassportNumber")]
    pub passport_number: Option<String>,
    #[serde(default, alias = "LicenseNumber")]
    pub license_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKey {
    #[serde(default, alias = "PrivateKey")]
    pub private_key: Option<String>,
    #[serde(default, alias = "PublicKey")]
    pub public_key: Option<String>,
    /// The fingerprint. On the wire it is called `keyFingerprint`, and
    /// **only** that: while the aliases held just `KeyFingerprint` and
    /// `Fingerprint`, the fingerprint read for no key at all (the card showed
    /// nothing), and on a write it went back as `null` — so binding a host to a
    /// key erased the fingerprint for every other client too.
    #[serde(
        rename = "keyFingerprint",
        default,
        alias = "KeyFingerprint",
        alias = "fingerprint",
        alias = "Fingerprint"
    )]
    pub fingerprint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server answers now in PascalCase (the old API), now in camelCase.
    /// Both have to parse, or the client breaks on a change of version.
    #[test]
    fn type_field_is_read_from_the_wire_name() {
        // The field is called `type`, not `kind`: a name of our own in the
        // struct must not silently turn every item into type zero.
        let s: Sync = serde_json::from_str(r#"{"ciphers":[{"id":"1","type":5,"name":"n"}]}"#).unwrap();
        assert_eq!(s.ciphers[0].kind, 5);
        let s: Sync = serde_json::from_str(r#"{"Ciphers":[{"Id":"1","Type":3,"Name":"n"}]}"#).unwrap();
        assert_eq!(s.ciphers[0].kind, 3);
    }

    #[test]
    fn both_casings_parse() {
        let pascal = r#"{"Ciphers":[{"Id":"1","Type":1,"Name":"enc","DeletedDate":"2026-01-01","Favorite":true}]}"#;
        let camel = r#"{"ciphers":[{"id":"1","type":1,"name":"enc","deletedDate":"2026-01-01","favorite":true}]}"#;
        for body in [pascal, camel] {
            let s: Sync = serde_json::from_str(body).expect("parses");
            assert_eq!(s.ciphers.len(), 1);
            assert!(s.ciphers[0].in_trash());
            assert!(s.ciphers[0].favorite);
        }
    }

    #[test]
    fn explicit_nulls_do_not_break_the_whole_sync() {
        // A real answer from the server: an item with no addresses comes with
        // `"uris": null`, and the whole vault's parse fell over on it.
        let body = r#"{
            "ciphers": [{
                "id": "1", "type": 1, "name": "enc",
                "login": {"username": null, "uris": null},
                "fields": null, "collectionIds": null
            }],
            "folders": null,
            "collections": null,
            "profile": {"organizations": null}
        }"#;
        let s: Sync = serde_json::from_str(body).expect("a null must not break the parse");
        assert_eq!(s.ciphers.len(), 1);
        assert!(s.ciphers[0].fields.is_empty());
        assert!(s.ciphers[0].collection_ids.is_empty());
        assert!(s.ciphers[0].login.as_ref().unwrap().uris.is_empty());
        assert!(s.folders.is_empty() && s.collections.is_empty());
    }

    #[test]
    fn missing_sections_are_not_an_error() {
        // An empty vault and a cut-down answer must not break the parse.
        let s: Sync = serde_json::from_str("{}").expect("parses");
        assert!(s.ciphers.is_empty() && s.folders.is_empty() && s.collections.is_empty());
    }

    #[test]
    fn a_custom_roles_permissions_are_read() {
        let o: Organization = serde_json::from_str(r#"{"id":"o","type":4,"permissions":{"manageUsers":true}}"#).unwrap();
        assert!(o.kind == 4 && o.permissions.manage_users);
        let o: Organization = serde_json::from_str(r#"{"id":"o","type":1,"permissions":null}"#).unwrap();
        assert!(!o.permissions.manage_users);
    }

    #[test]
    fn trash_is_detected_by_deleted_date() {
        let c: Cipher = serde_json::from_str(r#"{"id":"1","name":"n"}"#).unwrap();
        assert!(!c.in_trash());
    }

    // --- the server's answer as untrusted data -------------------------------
    //
    // The server -- or whoever took its place -- is free to send anything. The
    // cost of a mistake here is lopsided: if the parse falls over whole, the
    // client quietly stays on its old snapshot -- no new items, no deleted
    // ones -- and the ssh agent goes on handing out keys from yesterday's
    // vault. So a crooked item is dropped one at a time, and its neighbours
    // must survive.

    #[test]
    fn one_crooked_item_does_not_take_the_whole_vault() {
        let body = r#"{"ciphers":[
            {"id":"1","name":"first"},
            {"type":1,"name":"no identifier"},
            {"id":"3","name":"third"}
        ]}"#;
        let s: Sync = serde_json::from_str(body).expect("the parse does not fall over");
        let ids: Vec<&str> = s.ciphers.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["1", "3"], "everything but the crooked one must survive");
    }

    #[test]
    fn a_field_of_the_wrong_type_drops_only_its_own_item() {
        // Each of these items used to break the whole of `/api/sync`.
        for bad in [
            r#"{"id":"x","type":"1"}"#,        // a string where a number belongs
            r#"{"id":"x","type":-1}"#,         // a negative type
            r#"{"id":"x","type":99999}"#,      // does not fit in a byte
            r#"{"id":"x","favorite":1}"#,      // a number where a flag belongs
            r#"{"id":"x","login":"no"}"#,      // a string where an object belongs
            r#"{"id":null,"name":"n"}"#,       // a null where an identifier belongs
            r#"{"id":7,"name":"n"}"#,          // a number where an identifier belongs
            r#"{"id":"x","deletedDate":0}"#,   // a number where a date belongs
            r#"[]"#,                           // not an item at all
        ] {
            let body = format!(r#"{{"ciphers":[{bad},{{"id":"alive","name":"n"}}]}}"#);
            let s: Sync = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{bad}: {e}"));
            assert_eq!(s.ciphers.len(), 1, "{bad}: the neighbouring item must survive");
            assert_eq!(s.ciphers[0].id, "alive");
        }
    }

    #[test]
    fn a_crooked_folder_organisation_or_collection_does_not_take_the_others() {
        let body = r#"{
            "folders":[{"name":"no id"},{"id":"f","name":"here"}],
            "collections":[{"id":null},{"id":"c","name":"here"}],
            "profile":{"organizations":[{"name":"no id"},{"id":"o","name":"here"}]}
        }"#;
        let s: Sync = serde_json::from_str(body).expect("the parse does not fall over");
        assert_eq!(s.folders.len(), 1);
        assert_eq!(s.collections.len(), 1);
        assert_eq!(s.profile.organizations.len(), 1);
    }

    #[test]
    fn something_that_is_not_a_list_arrived_where_a_list_belongs() {
        // `null` is covered already; here are an object and a string that
        // come out of nowhere but must not cost us the whole vault.
        let body = r#"{"ciphers":[{"id":"1","fields":{"a":1},
            "collectionIds":"no","login":{"uris":"no"}}]}"#;
        let s: Sync = serde_json::from_str(body).expect("the parse does not fall over");
        assert_eq!(s.ciphers.len(), 1);
        assert!(s.ciphers[0].fields.is_empty());
        assert!(s.ciphers[0].collection_ids.is_empty());
        assert!(s.ciphers[0].login.as_ref().unwrap().uris.is_empty());
    }

    #[test]
    fn a_null_profile_is_not_an_error() {
        let s: Sync = serde_json::from_str(r#"{"profile":null,"ciphers":[]}"#).expect("parses");
        assert!(s.profile.id.is_empty());
    }

    #[test]
    fn an_empty_deletion_date_does_not_mean_the_trash() {
        // A `"deletedDate": ""` from the server swept the whole vault into
        // the trash at a stroke.
        let s: Sync = serde_json::from_str(r#"{"ciphers":[
            {"id":"1","deletedDate":""},
            {"id":"2","deletedDate":"   "},
            {"id":"3","deletedDate":"2026-01-01T00:00:00Z"}
        ]}"#).unwrap();
        assert!(!s.ciphers[0].in_trash());
        assert!(!s.ciphers[1].in_trash());
        assert!(s.ciphers[2].in_trash());
    }

    #[test]
    fn extra_fields_at_any_level_do_not_get_in_the_way() {
        let body = r#"{
            "unknownTop":123,
            "object":"sync",
            "ciphers":[{"id":"1","name":"n","object":"cipher","edit":true,
                "viewPassword":false,"data":{"something":"foreign"},
                "login":{"username":"u","unfamiliar":[1,2,3]},
                "fields":[{"type":1,"name":"n","value":"v","foreign":true}]}]
        }"#;
        let s: Sync = serde_json::from_str(body).expect("parses");
        assert_eq!(s.ciphers.len(), 1);
        assert_eq!(s.ciphers[0].fields.len(), 1);
    }

    #[test]
    fn duplicate_identifiers_are_kept_as_they_are() {
        // There is no deduplication, and that is worth knowing: everywhere an
        // item is looked up by id, the first match is taken. A server that sent
        // two `x`s decides which of them an edit lands on and which a
        // deletion.
        let s: Sync = serde_json::from_str(r#"{"ciphers":[
            {"id":"x","name":"alive"},
            {"id":"x","name":"in the trash","deletedDate":"2026-01-01T00:00:00Z"}
        ]}"#).unwrap();
        assert_eq!(s.ciphers.len(), 2);
        let first = s.ciphers.iter().find(|c| c.id == "x").unwrap();
        assert!(!first.in_trash());
        assert!(s.ciphers.iter().any(|c| c.id == "x" && c.in_trash()));
    }

    #[test]
    fn unicode_and_very_long_values_are_survived() {
        let long = "\u{416}".repeat(200_000);
        let body = serde_json::json!({
            "ciphers": [{
                "id": "1",
                "name": long,
                "notes": "\u{7}a line\nbreak\tand tabs",
                "login": {"username": "🎉", "uris": [{"uri": "🙂", "match": 255}]},
                "card": {"expMonth": "1", "expYear": "🎉"}
            }]
        })
        .to_string();
        let s: Sync = serde_json::from_str(&body).expect("parses");
        assert_eq!(s.ciphers[0].name.chars().count(), 200_000);
        assert_eq!(s.ciphers[0].card.as_ref().unwrap().exp_year.as_deref(), Some("🎉"));
    }

    #[test]
    fn a_large_vault_parses_whole() {
        let items: Vec<serde_json::Value> = (0..20_000)
            .map(|i| serde_json::json!({"id": i.to_string(), "type": 1, "name": "n"}))
            .collect();
        let body = serde_json::json!({ "ciphers": items }).to_string();
        let s: Sync = serde_json::from_str(&body).expect("parses");
        assert_eq!(s.ciphers.len(), 20_000);
    }

    #[test]
    fn an_ssh_keys_fingerprint_is_read_off_the_wire() {
        // The server calls this field `keyFingerprint`. While the parse did
        // not know it, the fingerprint was empty for every key of the vault --
        // and went back as `null`, erasing it on the server on any edit.
        let s: Sync = serde_json::from_str(
            r#"{"ciphers":[{"id":"1","type":5,"sshKey":{"keyFingerprint":"2.fingerprint"}}]}"#,
        )
        .unwrap();
        assert_eq!(
            s.ciphers[0].ssh_key.as_ref().unwrap().fingerprint.as_deref(),
            Some("2.fingerprint")
        );

        // The snapshot on disk is our own output, so the name has to match
        // the wire, or the fingerprint is lost on the very first re-read.
        let again: Sync = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(
            again.ciphers[0].ssh_key.as_ref().unwrap().fingerprint.as_deref(),
            Some("2.fingerprint")
        );
    }

    #[test]
    fn deep_nesting_does_not_blow_the_stack() {
        // An answer with thousands of nested brackets must end in an error
        // rather than a stack overflow: the parse is recursive.
        let deep = format!("{}{}", "[".repeat(20_000), "]".repeat(20_000));
        let body = format!(r#"{{"ciphers":[{{"id":"1","foreign":{deep}}}]}}"#);
        assert!(serde_json::from_str::<Sync>(&body).is_err());
    }
}
