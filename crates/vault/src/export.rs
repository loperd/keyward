//! Exporting the vault in the clear, in Bitwarden's formats.
//!
//! The JSON repeats the official client's unencrypted export: the same set of
//! fields on an item, under the same names, so that the file can be imported
//! back into Bitwarden or into any manager that understands the format. The
//! CSV is its one too: exactly the columns its importer expects.
//!
//! The trash does not go into an export, just as in Bitwarden: what a person
//! deleted, they deleted. keyward's own service items (`kw-hidden`) do go in:
//! they are that person's data, and an export is obliged to be complete.

use keyward_bw::model::{Cipher, Sync};
use keyward_core::account::ExportFormat;

use crate::read::Ring;

/// A decrypted folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainFolder {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlainField {
    pub name: Option<String>,
    pub value: Option<String>,
    pub kind: u8,
    pub linked_id: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlainUri {
    pub uri: Option<String>,
    pub match_type: Option<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlainLogin {
    pub uris: Vec<PlainUri>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlainCard {
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlainIdentity {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssn: Option<String>,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlainSshKey {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
}

/// A decrypted item: exactly what goes into the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlainItem {
    pub id: String,
    pub organization_id: Option<String>,
    pub folder_id: Option<String>,
    /// 1 login, 2 note, 3 card, 4 identity, 5 ssh key.
    pub kind: u8,
    pub name: String,
    pub notes: Option<String>,
    pub favorite: bool,
    pub reprompt: u8,
    pub fields: Vec<PlainField>,
    pub login: Option<PlainLogin>,
    pub card: Option<PlainCard>,
    pub identity: Option<PlainIdentity>,
    pub ssh_key: Option<PlainSshKey>,
    pub collection_ids: Vec<String>,
    pub creation_date: Option<String>,
    pub revision_date: Option<String>,
    pub deleted_date: Option<String>,
}

/// Decrypts a whole snapshot. An item whose key did not open is skipped with
/// a warning: an incomplete export beats none at all.
pub fn decrypt_all(snapshot: &Sync, ring: &Ring<'_>) -> (Vec<PlainFolder>, Vec<PlainItem>) {
    let folders = snapshot
        .folders
        .iter()
        .map(|f| PlainFolder {
            id: f.id.clone(),
            name: crate::read::decrypt(&f.name, ring.user, None).unwrap_or_else(|| f.name.clone()),
        })
        .collect();

    let mut items = Vec::with_capacity(snapshot.ciphers.len());
    for cipher in &snapshot.ciphers {
        if cipher.in_trash() {
            continue;
        }
        match plain_item(cipher, ring) {
            Some(item) => items.push(item),
            None => tracing::warn!(entry = %cipher.id, "the item did not decrypt and did not reach the export"),
        }
    }
    (folders, items)
}

fn plain_item(cipher: &Cipher, ring: &Ring<'_>) -> Option<PlainItem> {
    let keys = ring.base(cipher.organization_id.as_deref())?;
    let item_key = ring.item(cipher);
    // If the item has a key of its own that could not be opened, the fields
    // would read as rubbish: skipping the item is the honest thing.
    if cipher.key.is_some() && item_key.is_none() {
        return None;
    }
    let ik = item_key.as_ref();
    let dec = |v: &Option<String>| v.as_deref().and_then(|v| crate::read::decrypt(v, keys, ik));

    let name = crate::read::decrypt(&cipher.name, keys, ik)?;
    let kind = match cipher.kind {
        1..=5 => cipher.kind,
        _ if cipher.card.is_some() => 3,
        _ if cipher.identity.is_some() => 4,
        _ if cipher.ssh_key.is_some() => 5,
        _ if cipher.login.is_some() => 1,
        _ => 2,
    };

    Some(PlainItem {
        id: cipher.id.clone(),
        organization_id: cipher.organization_id.clone(),
        folder_id: cipher.folder_id.clone(),
        kind,
        name,
        notes: dec(&cipher.notes),
        favorite: cipher.favorite,
        reprompt: cipher.reprompt,
        fields: cipher
            .fields
            .iter()
            .map(|f| PlainField {
                name: dec(&f.name),
                // A linked field has no value by definition.
                value: if f.kind == 3 { None } else { dec(&f.value) },
                kind: f.kind,
                linked_id: f.linked_id,
            })
            .collect(),
        login: cipher.login.as_ref().map(|l| PlainLogin {
            uris: l
                .uris
                .iter()
                .map(|u| PlainUri { uri: dec(&u.uri), match_type: u.match_type })
                .collect(),
            username: dec(&l.username),
            password: dec(&l.password),
            totp: dec(&l.totp),
        }),
        card: cipher.card.as_ref().map(|c| PlainCard {
            cardholder_name: dec(&c.cardholder_name),
            brand: dec(&c.brand),
            number: dec(&c.number),
            exp_month: dec(&c.exp_month),
            exp_year: dec(&c.exp_year),
            code: dec(&c.code),
        }),
        identity: cipher.identity.as_ref().map(|i| PlainIdentity {
            title: dec(&i.title),
            first_name: dec(&i.first_name),
            middle_name: dec(&i.middle_name),
            last_name: dec(&i.last_name),
            address1: dec(&i.address1),
            address2: dec(&i.address2),
            address3: dec(&i.address3),
            city: dec(&i.city),
            state: dec(&i.state),
            postal_code: dec(&i.postal_code),
            country: dec(&i.country),
            company: dec(&i.company),
            email: dec(&i.email),
            phone: dec(&i.phone),
            ssn: dec(&i.ssn),
            username: dec(&i.username),
            passport_number: dec(&i.passport_number),
            license_number: dec(&i.license_number),
        }),
        ssh_key: cipher.ssh_key.as_ref().map(|k| PlainSshKey {
            private_key: dec(&k.private_key),
            public_key: dec(&k.public_key),
            fingerprint: dec(&k.fingerprint),
        }),
        collection_ids: cipher.collection_ids.clone(),
        creation_date: cipher.creation_date.clone(),
        revision_date: cipher.revision_date.clone(),
        deleted_date: cipher.deleted_date.clone(),
    })
}

/// Bitwarden's unencrypted JSON.
pub fn to_json(folders: &[PlainFolder], items: &[PlainItem]) -> String {
    use serde_json::{json, Value};

    let items: Vec<Value> = items
        .iter()
        .map(|it| {
            let mut v = json!({
                "passwordHistory": null,
                "revisionDate": it.revision_date,
                "creationDate": it.creation_date,
                "deletedDate": it.deleted_date,
                "id": it.id,
                "organizationId": it.organization_id,
                "folderId": it.folder_id,
                "type": it.kind,
                "reprompt": it.reprompt,
                "name": it.name,
                "notes": it.notes,
                "favorite": it.favorite,
                "collectionIds": it.collection_ids,
            });
            let obj = v.as_object_mut().expect("an object");
            if !it.fields.is_empty() {
                obj.insert(
                    "fields".into(),
                    json!(it
                        .fields
                        .iter()
                        .map(|f| json!({ "name": f.name, "value": f.value, "type": f.kind, "linkedId": f.linked_id }))
                        .collect::<Vec<_>>()),
                );
            }
            if let Some(l) = &it.login {
                obj.insert(
                    "login".into(),
                    json!({
                        "fido2Credentials": [],
                        "uris": l.uris.iter().map(|u| json!({ "match": u.match_type, "uri": u.uri })).collect::<Vec<_>>(),
                        "username": l.username,
                        "password": l.password,
                        "totp": l.totp,
                    }),
                );
            }
            if it.kind == 2 {
                obj.insert("secureNote".into(), json!({ "type": 0 }));
            }
            if let Some(c) = &it.card {
                obj.insert(
                    "card".into(),
                    json!({
                        "cardholderName": c.cardholder_name, "brand": c.brand, "number": c.number,
                        "expMonth": c.exp_month, "expYear": c.exp_year, "code": c.code,
                    }),
                );
            }
            if let Some(i) = &it.identity {
                obj.insert(
                    "identity".into(),
                    json!({
                        "title": i.title, "firstName": i.first_name, "middleName": i.middle_name,
                        "lastName": i.last_name, "address1": i.address1, "address2": i.address2,
                        "address3": i.address3, "city": i.city, "state": i.state,
                        "postalCode": i.postal_code, "country": i.country, "company": i.company,
                        "email": i.email, "phone": i.phone, "ssn": i.ssn, "username": i.username,
                        "passportNumber": i.passport_number, "licenseNumber": i.license_number,
                    }),
                );
            }
            if let Some(k) = &it.ssh_key {
                obj.insert(
                    "sshKey".into(),
                    json!({ "privateKey": k.private_key, "publicKey": k.public_key, "keyFingerprint": k.fingerprint }),
                );
            }
            v
        })
        .collect();

    let doc = json!({
        "encrypted": false,
        "folders": folders.iter().map(|f| json!({ "id": f.id, "name": f.name })).collect::<Vec<_>>(),
        "items": items,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// Bitwarden's CSV header, in exactly this order.
pub const CSV_HEADER: &str =
    "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp";

/// Bitwarden's CSV. There are no ssh keys in it: the format has no column for
/// a private key, and putting one in the notes would breed copies of a
/// secret.
pub fn to_csv(folders: &[PlainFolder], items: &[PlainItem]) -> String {
    let mut out = String::from(CSV_HEADER);
    out.push('\n');
    for it in items {
        let kind = match it.kind {
            1 => "login",
            2 => "note",
            3 => "card",
            4 => "identity",
            _ => continue,
        };
        let folder = it
            .folder_id
            .as_deref()
            .and_then(|id| folders.iter().find(|f| f.id == id))
            .map(|f| f.name.as_str())
            .unwrap_or("");
        let fields = it
            .fields
            .iter()
            .map(|f| format!("{}: {}", f.name.as_deref().unwrap_or(""), f.value.as_deref().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("\n");
        let login = it.login.as_ref();
        let uris = login
            .map(|l| l.uris.iter().filter_map(|u| u.uri.as_deref()).collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        let row = [
            folder,
            if it.favorite { "1" } else { "" },
            kind,
            it.name.as_str(),
            it.notes.as_deref().unwrap_or(""),
            fields.as_str(),
            if it.reprompt != 0 { "1" } else { "0" },
            uris.as_str(),
            login.and_then(|l| l.username.as_deref()).unwrap_or(""),
            login.and_then(|l| l.password.as_deref()).unwrap_or(""),
            login.and_then(|l| l.totp.as_deref()).unwrap_or(""),
        ];
        out.push_str(&row.iter().map(|c| csv_cell(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

/// A CSV cell: anything that would otherwise break parsing is quoted. A
/// leading `=`, `+`, `-` or `@` too, or a spreadsheet would run the cell as a
/// formula.
fn csv_cell(value: &str) -> String {
    let risky = value.contains([',', '"', '\n', '\r'])
        || value.starts_with(['=', '+', '-', '@', '\t']);
    if !risky {
        return value.to_string();
    }
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// A file name like Bitwarden's: `bitwarden_export_YYYYMMDDHHMMSS.json`.
pub fn filename(format: ExportFormat, unix_secs: u64) -> String {
    let (y, mo, d, h, mi, s) = civil(unix_secs);
    let ext = match format {
        ExportFormat::Json => "json",
        ExportFormat::Csv => "csv",
    };
    format!("bitwarden_export_{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}.{ext}")
}

/// A calendar date out of Unix seconds (UTC), without an external crate:
/// Howard Hinnant's algorithm for days since the epoch.
fn civil(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, (rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(name: &str) -> PlainItem {
        PlainItem {
            id: "i1".into(),
            kind: 1,
            name: name.into(),
            folder_id: Some("f1".into()),
            favorite: true,
            fields: vec![PlainField { name: Some("api".into()), value: Some("a key".into()), kind: 1, linked_id: None }],
            login: Some(PlainLogin {
                uris: vec![
                    PlainUri { uri: Some("https://a.example".into()), match_type: None },
                    PlainUri { uri: Some("https://b.example".into()), match_type: Some(0) },
                ],
                username: Some("me".into()),
                password: Some("p,w\"d".into()),
                totp: Some("JBSWY3DP".into()),
            }),
            ..Default::default()
        }
    }

    fn folders() -> Vec<PlainFolder> {
        vec![PlainFolder { id: "f1".into(), name: "Work".into() }]
    }

    #[test]
    fn a_csv_header_and_one_row() {
        let csv = to_csv(&folders(), &[login("Site")]);
        let mut lines = csv.lines();
        assert_eq!(lines.next().unwrap(), CSV_HEADER);
        let row = lines.next().unwrap();
        assert_eq!(
            row,
            "Work,1,login,Site,,api: a key,0,\"https://a.example,https://b.example\",me,\"p,w\"\"d\",JBSWY3DP"
        );
        assert!(lines.next().is_none());
    }

    #[test]
    fn several_csv_fields_are_quoted_across_a_line_break() {
        let mut it = login("x");
        it.fields.push(PlainField { name: Some("b".into()), value: Some("2".into()), kind: 0, linked_id: None });
        let csv = to_csv(&[], &[it]);
        assert!(csv.contains("\"api: a key\nb: 2\""), "{csv}");
    }

    #[test]
    fn csv_leaves_ssh_keys_out_but_keeps_cards_and_identities() {
        let ssh = PlainItem { id: "s".into(), kind: 5, name: "a key".into(), ..Default::default() };
        let card = PlainItem { id: "c".into(), kind: 3, name: "a card".into(), ..Default::default() };
        let who = PlainItem { id: "w".into(), kind: 4, name: "me".into(), ..Default::default() };
        let note = PlainItem { id: "n".into(), kind: 2, name: "a note".into(), reprompt: 1, ..Default::default() };
        let csv = to_csv(&[], &[ssh, card, who, note]);
        let rows: Vec<&str> = csv.lines().skip(1).collect();
        assert_eq!(rows, [",,card,a card,,,0,,,,", ",,identity,me,,,0,,,,", ",,note,a note,,,1,,,,"]);
    }

    #[test]
    fn csv_formulas_are_escaped() {
        assert_eq!(csv_cell("=1+1"), "\"=1+1\"");
        assert_eq!(csv_cell("-5"), "\"-5\"");
        assert_eq!(csv_cell("ordinary"), "ordinary");
    }

    #[test]
    fn the_json_has_bitwardens_shape() {
        let doc: serde_json::Value = serde_json::from_str(&to_json(&folders(), &[login("Site")])).unwrap();
        assert_eq!(doc["encrypted"], false);
        assert_eq!(doc["folders"][0]["name"], "Work");
        let it = &doc["items"][0];
        assert_eq!(it["type"], 1);
        assert_eq!(it["name"], "Site");
        assert_eq!(it["folderId"], "f1");
        assert_eq!(it["favorite"], true);
        assert_eq!(it["reprompt"], 0);
        assert_eq!(it["login"]["username"], "me");
        assert_eq!(it["login"]["password"], "p,w\"d");
        assert_eq!(it["login"]["totp"], "JBSWY3DP");
        assert_eq!(it["login"]["uris"][1]["match"], 0);
        assert_eq!(it["login"]["uris"][0]["uri"], "https://a.example");
        assert_eq!(it["fields"][0]["name"], "api");
        assert_eq!(it["fields"][0]["type"], 1);
        assert!(it["collectionIds"].is_array());
        assert!(it["deletedDate"].is_null());
        assert!(it.get("card").is_none() && it.get("identity").is_none() && it.get("sshKey").is_none());
    }

    #[test]
    fn json_covers_a_note_a_card_an_identity_and_a_key() {
        let note = PlainItem { id: "n".into(), kind: 2, name: "n".into(), notes: Some("text".into()), ..Default::default() };
        let card = PlainItem {
            id: "c".into(),
            kind: 3,
            name: "c".into(),
            card: Some(PlainCard { number: Some("4111".into()), exp_year: Some("2030".into()), ..Default::default() }),
            ..Default::default()
        };
        let who = PlainItem {
            id: "w".into(),
            kind: 4,
            name: "w".into(),
            identity: Some(PlainIdentity { first_name: Some("Name".into()), passport_number: Some("77".into()), ..Default::default() }),
            ..Default::default()
        };
        let ssh = PlainItem {
            id: "s".into(),
            kind: 5,
            name: "s".into(),
            ssh_key: Some(PlainSshKey { private_key: Some("PRIV".into()), public_key: Some("PUB".into()), fingerprint: Some("SHA256:x".into()) }),
            ..Default::default()
        };
        let doc: serde_json::Value = serde_json::from_str(&to_json(&[], &[note, card, who, ssh])).unwrap();
        assert_eq!(doc["items"][0]["secureNote"]["type"], 0);
        assert_eq!(doc["items"][0]["notes"], "text");
        assert_eq!(doc["items"][1]["card"]["number"], "4111");
        assert_eq!(doc["items"][1]["card"]["expYear"], "2030");
        assert_eq!(doc["items"][2]["identity"]["firstName"], "Name");
        assert_eq!(doc["items"][2]["identity"]["passportNumber"], "77");
        assert_eq!(doc["items"][3]["sshKey"]["privateKey"], "PRIV");
        assert_eq!(doc["items"][3]["sshKey"]["keyFingerprint"], "SHA256:x");
    }

    #[test]
    fn a_snapshot_decrypts_with_real_keys() {
        // A real user key and real rbw ciphertexts: the whole path is under
        // test, not only assembling JSON out of ready-made strings.
        let mut raw = rbw::locked::Vec::new();
        raw.extend(std::iter::repeat_n(7u8, 64));
        let user = rbw::locked::Keys::new(raw);
        let enc = |s: &str| rbw::cipherstring::CipherString::encrypt_symmetric(&user, s.as_bytes()).unwrap().to_string();
        let snapshot: Sync = serde_json::from_value(serde_json::json!({
            "folders": [{"id": "f", "name": enc("Folder")}],
            "ciphers": [
                {"id": "1", "type": 1, "name": enc("Login"), "folderId": "f", "favorite": true,
                 "login": {"username": enc("me"), "password": enc("pw"), "uris": [{"uri": enc("https://x")}]},
                 "fields": [{"type": 0, "name": enc("k"), "value": enc("v")}]},
                {"id": "2", "type": 2, "name": enc("In the trash"), "deletedDate": "2026-01-01T00:00:00Z"},
                {"id": "3", "type": 2, "name": "not a ciphertext"}
            ]
        }))
        .unwrap();
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let (folders, items) = decrypt_all(&snapshot, &ring);
        assert_eq!(folders, vec![PlainFolder { id: "f".into(), name: "Folder".into() }]);
        assert_eq!(items.len(), 1, "the trash and the undecryptable stay out");
        assert_eq!(items[0].name, "Login");
        assert_eq!(items[0].login.as_ref().unwrap().password.as_deref(), Some("pw"));
        assert_eq!(items[0].fields[0].value.as_deref(), Some("v"));
        let csv = to_csv(&folders, &items);
        assert!(csv.lines().nth(1).unwrap().starts_with("Folder,1,login,Login,,k: v,0,https://x,me,pw,"));
    }

    #[test]
    fn the_file_name_and_the_calendar() {
        // 2026-09-09 23:05:07 UTC, checked against `date -u -r 1788995107`.
        assert_eq!(filename(ExportFormat::Json, 1_788_995_107), "bitwarden_export_20260909230507.json");
        assert_eq!(filename(ExportFormat::Csv, 0), "bitwarden_export_19700101000000.csv");
        // A leap day and the end of a year.
        let (y, m, d, _, _, _) = civil(1_709_164_800);
        assert_eq!((y, m, d), (2024, 2, 29));
        assert_eq!(civil(1_735_689_599), (2024, 12, 31, 23, 59, 59));
    }
}
