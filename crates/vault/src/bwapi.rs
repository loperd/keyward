//! Writing items back to Bitwarden.
//!
//! Our own, not `rbw`'s: its `api::edit` has an `unreachable!()` for ssh
//! keys, meaning it cannot edit them at all, and it took the daemon down with
//! it on the first attempt to bind a host to a key. Dragging in fifteen
//! hundred lines of somebody else's api client for one branch is pointless,
//! and a request to change an item takes a couple of dozen lines.
//!
//! Asynchronous: a synchronous `reqwest` panics inside the runtime.

use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);

use keyward_bw::model::{Cipher, Field};

/// The body of a request to create or change an item.
///
/// The values here are already encrypted; this layer does not touch them. The
/// model is ours, so every kind of item is supported without exception, where
/// `rbw` panicked on ssh keys with `unreachable!()`.
fn cipher_json(c: &Cipher) -> serde_json::Value {
    let field_json = |f: &Field| {
        serde_json::json!({
            "type": f.kind,
            "name": f.name,
            "value": f.value,
            "linkedId": f.linked_id,
        })
    };

    let mut body = serde_json::json!({
        "type": c.kind,
        "name": c.name,
        "notes": c.notes,
        "folderId": c.folder_id,
        "organizationId": c.organization_id,
        "favorite": c.favorite,
        "reprompt": c.reprompt,
        // An item's own key must go back. The server assigns `key` exactly
        // what arrived: not sending it means clearing the key everything else
        // in that item is encrypted with, after which nobody can decrypt it.
        "key": c.key,
        // We do not show password history, but erasing it is not ours to do.
        "passwordHistory": c.password_history,
        "fields": c.fields.iter().map(field_json).collect::<Vec<_>>(),
    });
    let obj = body.as_object_mut().expect("an object");

    if let Some(l) = &c.login {
        obj.insert(
            "login".into(),
            serde_json::json!({
                "username": l.username,
                "password": l.password,
                "totp": l.totp,
                "uris": l.uris.iter().map(|u| serde_json::json!({
                    "uri": u.uri,
                    "match": u.match_type,
                })).collect::<Vec<_>>(),
                // A passkey goes back untouched: the server replaces the
                // login part whole, so anything we did not send disappears,
                // and a lost passkey cannot be recovered by anything.
                "fido2Credentials": l.fido2_credentials,
                "passwordRevisionDate": l.password_revision_date,
                "autofillOnPageLoad": l.autofill_on_page_load,
            }),
        );
    }
    if let Some(card) = &c.card {
        obj.insert(
            "card".into(),
            serde_json::json!({
                "cardholderName": card.cardholder_name,
                "number": card.number,
                "brand": card.brand,
                "expMonth": card.exp_month,
                "expYear": card.exp_year,
                "code": card.code,
            }),
        );
    }
    if let Some(i) = &c.identity {
        obj.insert(
            "identity".into(),
            serde_json::json!({
                "title": i.title, "firstName": i.first_name, "middleName": i.middle_name,
                "lastName": i.last_name, "email": i.email, "phone": i.phone,
                "username": i.username,
                // We show three of these fields but send them all back: the
                // address, the company and the passport number used to vanish
                // on a rename.
                "address1": i.address1, "address2": i.address2, "address3": i.address3,
                "city": i.city, "state": i.state, "postalCode": i.postal_code,
                "country": i.country, "company": i.company, "ssn": i.ssn,
                "passportNumber": i.passport_number, "licenseNumber": i.license_number,
            }),
        );
    }
    if let Some(k) = &c.ssh_key {
        obj.insert(
            "sshKey".into(),
            serde_json::json!({
                "privateKey": k.private_key,
                "publicKey": k.public_key,
                "keyFingerprint": k.fingerprint,
            }),
        );
    }
    if c.kind == 2 && c.secure_note.is_none() {
        obj.insert("secureNote".into(), serde_json::json!({ "type": 0 }));
    } else if let Some(n) = &c.secure_note {
        obj.insert("secureNote".into(), n.clone());
    }

    body
}

fn client() -> anyhow::Result<reqwest::Client> {
    // The same headers as on reading: the server decides from them which
    // kinds of item it is willing to accept.
    keyward_bw::client::build(TIMEOUT)
}

/// A server error in a form one can act on. 401 is singled out: it means "the
/// token has expired" and is cured by a sync, not by trying again.
#[derive(Debug)]
pub enum WriteError {
    Unauthorized,
    Other(anyhow::Error),
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "err.sessionExpired"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

async fn send(req: reqwest::RequestBuilder) -> Result<(), WriteError> {
    let res = req
        .send()
        .await
        .map_err(|e| WriteError::Other(anyhow::anyhow!("the server is unreachable: {e}")))?;
    let status = res.status();
    if status.is_success() {
        return Ok(());
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(WriteError::Unauthorized);
    }
    let body = res.text().await.unwrap_or_default();
    let detail = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("Message"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| body.chars().take(200).collect());
    Err(WriteError::Other(anyhow::anyhow!("the server answered {status}: {detail}")))
}

/// An identifier that will not walk the request off to somebody else's
/// endpoint.
///
/// It goes straight into the path, and `Url` normalises `..` before sending:
/// with `../../` inside, `PUT /api/ciphers/{id}/delete` leaves for a quite
/// different address and carries our bearer token there. The server issues
/// identifiers and they are UUIDs, so the check touches no real item.
fn path_id(id: &str) -> Result<&str, WriteError> {
    if keyward_bw::client::is_path_id(id) {
        Ok(id)
    } else {
        Err(WriteError::Other(anyhow::anyhow!("that is not a valid item identifier")))
    }
}

/// Changing an item that exists.
pub async fn put_cipher(base_url: &str, access_token: &str, cipher: &Cipher) -> Result<(), WriteError> {
    let url = format!("{}/api/ciphers/{}", base_url.trim_end_matches('/'), path_id(&cipher.id)?);
    let body = cipher_json(cipher);
    let http = client().map_err(WriteError::Other)?;
    send(http.put(url).bearer_auth(access_token).json(&body)).await
}

/// Into the trash. The item stays on the server but is marked deleted.
pub async fn trash_cipher(base_url: &str, access_token: &str, id: &str) -> Result<(), WriteError> {
    let id = path_id(id)?;
    let url = format!("{}/api/ciphers/{id}/delete", base_url.trim_end_matches('/'));
    let http = client().map_err(WriteError::Other)?;
    send(http.put(url).bearer_auth(access_token)).await
}

/// Back out of the trash.
pub async fn restore_cipher(base_url: &str, access_token: &str, id: &str) -> Result<(), WriteError> {
    let id = path_id(id)?;
    let url = format!("{}/api/ciphers/{id}/restore", base_url.trim_end_matches('/'));
    let http = client().map_err(WriteError::Other)?;
    send(http.put(url).bearer_auth(access_token)).await
}

/// For good. One request for every item: the trash is emptied whole more
/// often than one item at a time, and a hundred separate requests are a
/// hundred chances to break off halfway.
pub async fn purge_ciphers(
    base_url: &str,
    access_token: &str,
    ids: &[String],
) -> Result<(), WriteError> {
    let http = client().map_err(WriteError::Other)?;
    let url = format!("{}/api/ciphers", base_url.trim_end_matches('/'));
    for id in ids {
        path_id(id)?;
    }
    let body = serde_json::json!({ "ids": ids });
    match send(http.delete(&url).bearer_auth(access_token).json(&body)).await {
        Ok(()) => Ok(()),
        Err(WriteError::Unauthorized) => Err(WriteError::Unauthorized),
        // The server may not know the batch endpoint; then one at a time.
        Err(_) => {
            for id in ids {
                let id = path_id(id)?;
                let one = format!("{}/api/ciphers/{id}", base_url.trim_end_matches('/'));
                send(http.delete(one).bearer_auth(access_token)).await?;
            }
            Ok(())
        }
    }
}

/// Creating an item.
pub async fn post_cipher(base_url: &str, access_token: &str, cipher: &Cipher) -> Result<(), WriteError> {
    let url = format!("{}/api/ciphers", base_url.trim_end_matches('/'));
    let body = cipher_json(cipher);
    let http = client().map_err(WriteError::Other)?;
    send(http.post(url).bearer_auth(access_token).json(&body)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server's answer for an item, taken from a live vault but with
    /// everything we do not show: the item's own key, password history, a
    /// passkey, a full address.
    fn cipher_from(raw: &str) -> Cipher {
        serde_json::from_str(raw).expect("the item parses")
    }

    // --- read, edit, write must lose nothing --------------------------------
    //
    // On `PUT /api/ciphers/{id}` the server does not merge what arrived with
    // what it has; it replaces the item whole: `cipher.key = data.key`, and the
    // type's contents become a string built from what came in. So anything we
    // did not send disappears for the person, and renaming an item erases
    // things we never even knew about.

    #[test]
    fn an_items_own_key_goes_back_to_the_server() {
        // Without this field the server clears the key everything else in
        // the item is encrypted with, and there is nothing left to decrypt it
        // with.
        let c = cipher_from(r#"{"id":"1","name":"enc","key":"2.iv|ct|mac"}"#);
        let body = cipher_json(&c);
        assert_eq!(body["key"], "2.iv|ct|mac");
    }

    #[test]
    fn an_edit_does_not_erase_password_history() {
        let c = cipher_from(
            r#"{"id":"1","name":"enc","passwordHistory":[{"password":"2.old","lastUsedDate":"2026-01-01T00:00:00Z"}]}"#,
        );
        let body = cipher_json(&c);
        assert_eq!(body["passwordHistory"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn a_passkey_survives_a_rename() {
        // A lost passkey cannot be recovered by anything: it is the only
        // copy of that key, and the server has no second one.
        let c = cipher_from(
            r#"{"id":"1","name":"enc","login":{"username":"2.u","fido2Credentials":
                [{"credentialId":"2.cid","keyValue":"2.secret","rpId":"2.example.com"}],
                "passwordRevisionDate":"2026-01-01T00:00:00Z","autofillOnPageLoad":true}}"#,
        );
        let body = cipher_json(&c);
        assert_eq!(body["login"]["fido2Credentials"][0]["keyValue"], "2.secret");
        assert_eq!(body["login"]["passwordRevisionDate"], "2026-01-01T00:00:00Z");
        assert_eq!(body["login"]["autofillOnPageLoad"], true);
    }

    #[test]
    fn an_identity_is_written_whole_and_not_as_three_fields() {
        // We show the name, the email and the phone out of this. The
        // address, the company, the passport number and the SSN used to vanish
        // on any edit of the item.
        let raw = r#"{"id":"1","type":4,"name":"enc","identity":{
            "title":"2.t","firstName":"2.f","middleName":"2.m","lastName":"2.l",
            "email":"2.e","phone":"2.p","username":"2.u",
            "address1":"2.a1","address2":"2.a2","address3":"2.a3","city":"2.city",
            "state":"2.state","postalCode":"2.zip","country":"2.country",
            "company":"2.co","ssn":"2.ssn","passportNumber":"2.pass","licenseNumber":"2.lic"}}"#;
        let sent = cipher_json(&cipher_from(raw))["identity"].clone();
        let original: serde_json::Value = serde_json::from_str(raw).unwrap();
        for (key, value) in original["identity"].as_object().unwrap() {
            assert_eq!(&sent[key], value, "the field {key} was lost on the way to the server");
        }
    }

    #[test]
    fn an_ssh_key_and_custom_fields_arrive_as_they_are() {
        let c = cipher_from(
            r#"{"id":"1","type":5,"name":"enc","key":"2.iv|ct|mac",
                "sshKey":{"privateKey":"2.priv","publicKey":"2.pub","keyFingerprint":"2.fp"},
                "fields":[{"type":1,"name":"2.kw-host","value":"2.host","linkedId":null}]}"#,
        );
        let body = cipher_json(&c);
        assert_eq!(body["sshKey"]["privateKey"], "2.priv");
        assert_eq!(body["sshKey"]["keyFingerprint"], "2.fp");
        assert_eq!(body["fields"][0]["name"], "2.kw-host");
        assert_eq!(body["fields"][0]["type"], 1);
    }

    #[test]
    fn a_secure_note_with_no_part_of_its_own_is_given_one() {
        let body = cipher_json(&cipher_from(r#"{"id":"1","type":2,"name":"enc"}"#));
        assert_eq!(body["secureNote"]["type"], 0);
    }

    #[test]
    fn a_notes_contents_from_the_server_are_not_substituted() {
        let body =
            cipher_json(&cipher_from(r#"{"id":"1","type":2,"name":"enc","secureNote":{"type":1}}"#));
        assert_eq!(body["secureNote"]["type"], 1);
    }
}

#[cfg(test)]
mod url_tests {
    use super::*;

    #[test]
    fn an_item_identifier_cannot_be_a_piece_of_a_path() {
        // `Url` collapses `..` before sending, so an "identifier" like this
        // walks the request -- and the bearer token with it -- off to another
        // endpoint of the server.
        for bad in ["../../identity/connect/token", "a/b", "a?x=1", "a#y", "", "  "] {
            assert!(path_id(bad).is_err(), "accepted: {bad:?}");
        }
        assert!(path_id("6f4b2c1e-9a3d-4c7b-8e21-0f5a6b7c8d9e").is_ok());
    }
}
