//! Organisations: members and their roles.
//!
//! `/api/sync` brings only the organisations the account's owner belongs to and
//! says nothing about who else is in them. A separate endpoint gives the list
//! of members, and it is open only to those with the right to it in the
//! organisation — which is why an empty answer and a refusal are told apart.

use std::time::Duration;

use serde::Deserialize;

const TIMEOUT: Duration = Duration::from_secs(20);

/// A member of an organisation, as the server gives them.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgUser {
    #[serde(default, deserialize_with = "crate::model::null_as_default")]
    pub id: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// 0 invited, 1 accepted, 2 confirmed, -1 revoked. The server may send
    /// something we do not know: the value is kept as it is.
    #[serde(default, deserialize_with = "crate::model::null_as_default")]
    pub status: i32,
    /// 0 owner, 1 admin, 2 member, 3 manager, 4 a custom role.
    #[serde(default, rename = "type", deserialize_with = "crate::model::null_as_default")]
    pub kind: i32,
    #[serde(default, deserialize_with = "crate::model::null_as_default")]
    pub two_factor_enabled: bool,
    #[serde(default, deserialize_with = "crate::model::null_as_default")]
    pub access_all: bool,
    #[serde(default, deserialize_with = "crate::model::lenient_vec")]
    pub collections: Vec<OrgUserCollection>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgUserCollection {
    #[serde(default, deserialize_with = "crate::model::null_as_default")]
    pub id: String,
    #[serde(default, deserialize_with = "crate::model::null_as_default")]
    pub read_only: bool,
    #[serde(default, deserialize_with = "crate::model::null_as_default")]
    pub hide_passwords: bool,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    /// The same element-by-element parsing as in a snapshot: one member the
    /// server described against the rules must not hide the whole list, or the
    /// organisation looks unreachable while the access is there.
    #[serde(default, alias = "Data", deserialize_with = "crate::model::lenient_vec")]
    data: Vec<OrgUser>,
}

/// Parsing the `/api/organizations/{id}/users` answer apart from the request,
/// so that it can be tested without bringing a server up.
fn parse_users(body: &str) -> anyhow::Result<Vec<OrgUser>> {
    if !body.trim_start().starts_with('{') {
        anyhow::bail!("the list of members will not parse: the answer is not an object");
    }
    let envelope: Envelope = serde_json::from_str(body)
        .map_err(|e| anyhow::anyhow!("the list of members will not parse: {e}"))?;
    Ok(envelope.data)
}

/// An organisation's members. `Err` is a refusal from the server; an empty
/// `Ok` is an organisation with no members, which does not happen in practice:
/// there is always an owner.
pub async fn users(base_url: &str, access_token: &str, org_id: &str) -> anyhow::Result<Vec<OrgUser>> {
    if !crate::client::is_path_id(org_id) {
        anyhow::bail!("that is not a valid organisation identifier");
    }
    let http = crate::client::build(TIMEOUT)?;
    let url = format!("{}/api/organizations/{org_id}/users", base_url.trim_end_matches('/'));

    let res = http
        .get(url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("the server is unreachable: {e}"))?;

    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        anyhow::bail!("err.sessionExpired");
    }
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!("err.orgForbidden");
    }
    if !status.is_success() {
        anyhow::bail!("the server answered {status}");
    }

    parse_users(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_parses_vaultwardens_answer() {
        // The shape is taken from a live server: camelCase keys, a Data
        // envelope.
        let raw = r#"{"data":[{"id":"a","userId":"u","name":"Someone","email":"k@example.com",
            "status":2,"type":0,"twoFactorEnabled":false,"accessAll":true,"collections":[],
            "object":"organizationUserUserDetails"}],"object":"list"}"#;
        let parsed: Envelope = serde_json::from_str(raw).expect("parses");
        assert_eq!(parsed.data.len(), 1);
        assert_eq!(parsed.data[0].email.as_deref(), Some("k@example.com"));
        assert_eq!(parsed.data[0].kind, 0);
    }

    #[test]
    fn an_unknown_status_does_not_break_the_parse() {
        // The server sent 128: no such thing is documented, but falling over
        // is not allowed.
        let raw = r#"{"Data":[{"id":"a","status":128,"type":4}]}"#;
        let parsed: Envelope = serde_json::from_str(raw).expect("parses");
        assert_eq!(parsed.data[0].status, 128);
        assert_eq!(parsed.data[0].kind, 4);
    }

    // --- the members endpoint's answer as untrusted data ---------------------
    //
    // Here the cost of a parsing mistake is not an empty list but an `Err`,
    // and an `Err` from this endpoint the interface shows as "no access". So a
    // crooked answer looks like revoked rights, and a person goes off to mend
    // the wrong thing.

    #[test]
    fn a_null_instead_of_the_member_list_is_empty_not_an_error() {
        assert!(parse_users(r#"{"data":null}"#).expect("parses").is_empty());
        assert!(parse_users(r#"{"object":"list"}"#).expect("parses").is_empty());
        assert!(parse_users(r#"{"data":"no"}"#).expect("parses").is_empty());
    }

    #[test]
    fn one_crooked_member_does_not_hide_the_others() {
        let raw = r#"{"data":[
            {"id":"a","email":"a@example.com"},
            {"id":"b","status":"confirmed"},
            {"id":"c","type":null,"twoFactorEnabled":null,"collections":null},
            {"id":"d","email":"d@example.com"}
        ]}"#;
        let users = parse_users(raw).expect("parses");
        let ids: Vec<&str> = users.iter().map(|u| u.id.as_str()).collect();
        assert_eq!(ids, ["a", "c", "d"], "only the member with text in the status must fall out");
        assert!(users[1].collections.is_empty());
    }

    #[test]
    fn an_answer_that_is_not_an_object_is_an_error_not_an_empty_organisation() {
        // An empty list means "an organisation with no members", which does
        // not happen. Rubbish in place of an answer must not look like that.
        for raw in ["[]", "null", "\"ok\"", "42", "not json"] {
            assert!(parse_users(raw).is_err(), "{raw} must not parse");
        }
    }

    #[test]
    fn empty_strings_and_very_long_values() {
        let long = "\u{416}".repeat(100_000);
        let raw = serde_json::json!({
            "data": [{"id": "", "email": "", "name": long, "collections": []}]
        })
        .to_string();
        let users = parse_users(&raw).expect("parses");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name.as_ref().unwrap().chars().count(), 100_000);
    }

    #[test]
    fn extra_fields_and_both_cases_of_the_envelope() {
        for raw in [
            r#"{"data":[{"id":"a","object":"organizationUserUserDetails","foreign":{"x":1}}],"continuationToken":null}"#,
            r#"{"Data":[{"id":"a"}]}"#,
        ] {
            assert_eq!(parse_users(raw).expect("parses").len(), 1);
        }
    }
}

/// What the server needs in order to create an organisation.
///
/// Everything but the name and the email is cryptography: an organisation
/// lives on a symmetric key of its own, encrypted with the owner's public key,
/// and on an RSA pair of its own whose private half is encrypted with that very
/// symmetric key. That is how an owner can hand the organisation key to a new
/// member without knowing their password.
#[derive(Debug, Clone)]
pub struct NewOrg {
    pub name: String,
    pub billing_email: String,
    /// The organisation key, encrypted with the owner's public key (type 4).
    pub key: String,
    /// The organisation's public key, base64 of the DER.
    pub public_key: String,
    /// The organisation's private key, encrypted with the organisation key.
    pub encrypted_private_key: String,
    /// The name of the default collection, encrypted with the organisation
    /// key.
    pub collection_name: String,
}

/// Creates an organisation and returns its identifier.
pub async fn create(base_url: &str, access_token: &str, org: &NewOrg) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct Created {
        #[serde(default, alias = "Id")]
        id: String,
    }

    let body = serde_json::json!({
        "name": org.name,
        "billingEmail": org.billing_email,
        "collectionName": org.collection_name,
        "key": org.key,
        "keys": {
            "publicKey": org.public_key,
            "encryptedPrivateKey": org.encrypted_private_key,
        },
        // The free plan: Vaultwarden has no paid ones, and the official
        // server wants a subscription for a creation like this anyway.
        "planType": 0,
    });

    let text = send(base_url, access_token, reqwest::Method::POST, "api/organizations", Some(body)).await?;
    let created: Created = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("the answer about the created organisation will not parse: {e}"))?;
    if created.id.is_empty() {
        anyhow::bail!("the server returned no organisation identifier");
    }
    Ok(created.id)
}

/// Renaming, and changing the billing email.
pub async fn update(
    base_url: &str,
    access_token: &str,
    id: &str,
    name: &str,
    billing_email: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "name": name, "billingEmail": billing_email });
    let path = format!("api/organizations/{}", checked_id(id)?);
    send(base_url, access_token, reqwest::Method::PUT, &path, Some(body)).await?;
    Ok(())
}

/// Deleting an organisation.
///
/// The server asks for the master password hash: deleting takes every item of
/// the organisation away from every member, and a confirmation belongs here.
pub async fn delete(
    base_url: &str,
    access_token: &str,
    id: &str,
    master_password_hash: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "masterPasswordHash": master_password_hash });
    let path = format!("api/organizations/{}/delete", checked_id(id)?);
    send(base_url, access_token, reqwest::Method::POST, &path, Some(body)).await?;
    Ok(())
}

/// An identifier fit to go into a path.
pub(crate) fn checked_id(id: &str) -> anyhow::Result<&str> {
    if crate::client::is_path_id(id) {
        Ok(id)
    } else {
        Err(anyhow::anyhow!("that is not a valid identifier"))
    }
}

/// The shared wrapper: turning a server error into text one can act on.
pub(crate) async fn send(
    base_url: &str,
    access_token: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> anyhow::Result<String> {
    let http = crate::client::build(TIMEOUT)?;
    let url = format!("{}/{path}", base_url.trim_end_matches('/'));
    let mut req = http.request(method, url).bearer_auth(access_token);
    if let Some(body) = body {
        req = req.json(&body);
    }
    let res = req.send().await.map_err(|e| anyhow::anyhow!("the server is unreachable: {e}"))?;
    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        anyhow::bail!("err.sessionExpired");
    }
    if !status.is_success() {
        let detail = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("message")
                    .or_else(|| v.get("Message"))
                    .or_else(|| v.get("errorModel").and_then(|m| m.get("message")))
                    .and_then(|m| m.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| text.chars().take(200).collect());
        anyhow::bail!("the server answered {status}: {detail}");
    }
    Ok(text)
}

/// An organisation's collection.
///
/// The name is encrypted with the **organisation's** key rather than the
/// user's: every member of it has to be able to read a collection.
pub async fn create_collection(
    base_url: &str,
    access_token: &str,
    org_id: &str,
    encrypted_name: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "name": encrypted_name, "groups": [], "users": [] });
    let path = format!("api/organizations/{}/collections", checked_id(org_id)?);
    send(base_url, access_token, reqwest::Method::POST, &path, Some(body)).await?;
    Ok(())
}

pub async fn rename_collection(
    base_url: &str,
    access_token: &str,
    org_id: &str,
    collection_id: &str,
    encrypted_name: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "name": encrypted_name, "groups": [], "users": [] });
    let path = format!(
        "api/organizations/{}/collections/{}",
        checked_id(org_id)?,
        checked_id(collection_id)?
    );
    send(base_url, access_token, reqwest::Method::PUT, &path, Some(body)).await?;
    Ok(())
}

pub async fn delete_collection(
    base_url: &str,
    access_token: &str,
    org_id: &str,
    collection_id: &str,
) -> anyhow::Result<()> {
    let path = format!(
        "api/organizations/{}/collections/{}",
        checked_id(org_id)?,
        checked_id(collection_id)?
    );
    send(base_url, access_token, reqwest::Method::DELETE, &path, None).await?;
    Ok(())
}

/// Inviting a member.
///
/// The organisation key is not handed over yet: an invited person accepts the
/// invitation themselves, and only then does the owner confirm them by handing
/// over the key, encrypted with that member's own public key.
pub async fn invite(
    base_url: &str,
    access_token: &str,
    org_id: &str,
    email: &str,
    kind: i32,
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "emails": [email],
        "type": kind,
        "accessAll": true,
        "collections": [],
        "permissions": {},
    });
    let path = format!("api/organizations/{}/users/invite", checked_id(org_id)?);
    send(base_url, access_token, reqwest::Method::POST, &path, Some(body)).await?;
    Ok(())
}

/// Changing a member's role.
pub async fn set_role(
    base_url: &str,
    access_token: &str,
    org_id: &str,
    member_id: &str,
    kind: i32,
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "type": kind,
        "accessAll": true,
        "collections": [],
        "permissions": {},
    });
    let path = format!(
        "api/organizations/{}/users/{}",
        checked_id(org_id)?,
        checked_id(member_id)?
    );
    send(base_url, access_token, reqwest::Method::PUT, &path, Some(body)).await?;
    Ok(())
}

/// Removing a member.
pub async fn remove_member(
    base_url: &str,
    access_token: &str,
    org_id: &str,
    member_id: &str,
) -> anyhow::Result<()> {
    let path = format!(
        "api/organizations/{}/users/{}/delete",
        checked_id(org_id)?,
        checked_id(member_id)?
    );
    send(base_url, access_token, reqwest::Method::POST, &path, None).await?;
    Ok(())
}

/// A member's public key, needed in order to hand them the organisation key.
pub async fn user_public_key(
    base_url: &str,
    access_token: &str,
    user_id: &str,
) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct Res {
        #[serde(default, alias = "PublicKey")]
        public_key: String,
    }

    let path = format!("api/users/{}/public-key", checked_id(user_id)?);
    let text = send(base_url, access_token, reqwest::Method::GET, &path, None).await?;
    let parsed: Res = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("the member's public key will not parse: {e}"))?;
    if parsed.public_key.is_empty() {
        anyhow::bail!("the server returned no public key for the member");
    }
    Ok(parsed.public_key)
}

/// Confirming a member: the organisation key is handed to them, encrypted
/// with their own public key.
pub async fn confirm_member(
    base_url: &str,
    access_token: &str,
    org_id: &str,
    member_id: &str,
    sealed_org_key: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "key": sealed_org_key });
    let path = format!(
        "api/organizations/{}/users/{}/confirm",
        checked_id(org_id)?,
        checked_id(member_id)?
    );
    send(base_url, access_token, reqwest::Method::POST, &path, Some(body)).await?;
    Ok(())
}
