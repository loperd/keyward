//! The account: profile, master password, email, KDF, second factor, devices.
//!
//! Transport only: request bodies are assembled out of already computed hashes
//! and already encrypted keys, and answers are parsed into the server's raw
//! structures. What to show out of them and how is decided by `vault`, which
//! has the keys and the account's database.
//!
//! The routes and field names are checked against Vaultwarden's sources
//! (`api/core/accounts.rs`, `api/core/two_factor/*.rs`, `api/core/ciphers.rs`).
//! Every path is relative to `{base_url}/api`, and the JSON is camelCase.

use std::time::Duration;

use serde::Deserialize;

const TIMEOUT: Duration = Duration::from_secs(20);

/// The profile as `GET /accounts/profile` gives it.
///
/// Every field has a default: the server is free to send `null` anywhere, and
/// falling over because of an empty password hint would be silly.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(default, alias = "Id", deserialize_with = "crate::model::null_as_default")]
    pub id: String,
    #[serde(default, alias = "Email", deserialize_with = "crate::model::null_as_default")]
    pub email: String,
    #[serde(default, alias = "Name")]
    pub name: Option<String>,
    #[serde(default, alias = "EmailVerified", deserialize_with = "crate::model::null_as_default")]
    pub email_verified: bool,
    #[serde(default, alias = "Premium", deserialize_with = "crate::model::null_as_default")]
    pub premium: bool,
    #[serde(default, alias = "MasterPasswordHint")]
    pub master_password_hint: Option<String>,
    #[serde(default, alias = "AvatarColor")]
    pub avatar_color: Option<String>,
    #[serde(default, alias = "CreationDate")]
    pub creation_date: Option<String>,
    #[serde(default, alias = "TwoFactorEnabled", deserialize_with = "crate::model::null_as_default")]
    pub two_factor_enabled: bool,
    /// The public key, base64 of the DER. Vaultwarden does not put it here,
    /// but the official server does; we take it if it is there.
    #[serde(default, alias = "PublicKey")]
    pub public_key: Option<String>,
}

/// One second-factor method that is on, from `GET /two-factor`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorProvider {
    #[serde(default, alias = "Enabled", deserialize_with = "crate::model::null_as_default")]
    pub enabled: bool,
    #[serde(rename = "type", alias = "Type", default, deserialize_with = "crate::model::null_as_default")]
    pub kind: i32,
}

/// The answer of `POST /two-factor/get-authenticator` and
/// `PUT /two-factor/authenticator`.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authenticator {
    #[serde(default, alias = "Enabled", deserialize_with = "crate::model::null_as_default")]
    pub enabled: bool,
    #[serde(default, alias = "Key", deserialize_with = "crate::model::null_as_default")]
    pub key: String,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Authenticator {{ key: <hidden>, enabled: {} }}", self.enabled)
    }
}

/// The answer of `POST /two-factor/get-email` and `PUT /two-factor/email`.
///
/// After it is turned on, Vaultwarden sends `enabled` as the **string**
/// `"true"`, and on a read as a boolean. Both are parsed.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailTwoFactor {
    #[serde(default, alias = "Email")]
    pub email: Option<String>,
    #[serde(default, alias = "Enabled", deserialize_with = "bool_or_string")]
    pub enabled: bool,
}

fn bool_or_string<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match serde_json::Value::deserialize(d)? {
        serde_json::Value::Bool(b) => b,
        serde_json::Value::String(s) => s.trim().eq_ignore_ascii_case("true"),
        _ => false,
    })
}

/// A device out of `GET /devices`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    #[serde(default, alias = "Id", deserialize_with = "crate::model::null_as_default")]
    pub id: String,
    #[serde(default, alias = "Name")]
    pub name: Option<String>,
    /// Bitwarden's `DeviceType` as a number: 7 macOS, 8 Windows, 9 Linux...
    #[serde(rename = "type", alias = "Type", default, deserialize_with = "crate::model::null_as_default")]
    pub kind: i32,
    #[serde(default, alias = "Identifier", deserialize_with = "crate::model::null_as_default")]
    pub identifier: String,
    #[serde(default, alias = "CreationDate")]
    pub creation_date: Option<String>,
    /// Absent in Vaultwarden; the official server gives it.
    #[serde(default, alias = "RevisionDate")]
    pub revision_date: Option<String>,
}

impl Device {
    /// The class of device in words, from Bitwarden's `DeviceType` list.
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            0 | 1 | 15 | 16 => "mobile",
            2..=5 | 19 | 20 | 21 | 22 | 23 | 24 => "browser",
            6..=9 | 10 | 11 | 12 | 13 | 17 | 18 | 25 => "desktop",
            14 => "cli",
            _ => "unknown",
        }
    }
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "T: serde::de::DeserializeOwned"))]
struct Envelope<T> {
    #[serde(default, alias = "Data", deserialize_with = "crate::model::lenient_vec")]
    data: Vec<T>,
}

fn object<T: serde::de::DeserializeOwned>(body: &str, what: &str) -> anyhow::Result<T> {
    if !body.trim_start().starts_with('{') {
        anyhow::bail!("{what} will not parse: the answer is not an object");
    }
    serde_json::from_str(body).map_err(|e| anyhow::anyhow!("{what} will not parse: {e}"))
}

pub fn parse_profile(body: &str) -> anyhow::Result<Profile> {
    object(body, "the profile")
}

pub fn parse_two_factor(body: &str) -> anyhow::Result<Vec<TwoFactorProvider>> {
    let env: Envelope<TwoFactorProvider> = object(body, "the list of second factors")?;
    Ok(env.data)
}

pub fn parse_devices(body: &str) -> anyhow::Result<Vec<Device>> {
    let env: Envelope<Device> = object(body, "the list of devices")?;
    Ok(env.data)
}

fn parse_authenticator(body: &str) -> anyhow::Result<Authenticator> {
    let a: Authenticator = object(body, "the authenticator secret")?;
    if a.key.trim().is_empty() {
        anyhow::bail!("the server returned no authenticator secret");
    }
    Ok(a)
}

fn parse_email_two_factor(body: &str) -> anyhow::Result<EmailTwoFactor> {
    object(body, "the second factor email")
}

fn parse_recovery_code(body: &str) -> anyhow::Result<Option<String>> {
    #[derive(Deserialize)]
    struct Res {
        #[serde(default, alias = "Code")]
        code: Option<String>,
    }
    let r: Res = object(body, "the recovery code")?;
    Ok(r.code.filter(|c| !c.trim().is_empty()))
}

// -- The profile ----------------------------------------------------------

pub async fn profile(base_url: &str, access_token: &str) -> anyhow::Result<Profile> {
    let text = send(base_url, access_token, reqwest::Method::GET, "api/accounts/profile", None).await?;
    parse_profile(&text)
}

/// The name and the master password hint.
///
/// Vaultwarden does not read the hint at this endpoint (it changes together
/// with the password), but the official server accepts it, so both are sent.
pub async fn set_profile(
    base_url: &str,
    access_token: &str,
    name: &str,
    hint: Option<&str>,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "name": name, "masterPasswordHint": hint });
    send(base_url, access_token, reqwest::Method::PUT, "api/accounts/profile", Some(body)).await?;
    Ok(())
}

/// The avatar colour `#rrggbb`; `None` clears it.
pub async fn set_avatar(base_url: &str, access_token: &str, color: Option<&str>) -> anyhow::Result<()> {
    let body = serde_json::json!({ "avatarColor": color });
    send(base_url, access_token, reqwest::Method::PUT, "api/accounts/avatar", Some(body)).await?;
    Ok(())
}

// -- Master password, email, KDF -------------------------------------------

/// The KDF parameters in the protocol's terms: `kdf` is 0 for PBKDF2, 1 for
/// Argon2id.
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub kdf: i32,
    pub iterations: u32,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
}

impl KdfParams {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "kdfType": self.kdf,
            "iterations": self.iterations,
            "memory": self.memory,
            "parallelism": self.parallelism,
        })
    }
}

/// Changing what the user key is wrapped in: the password or the KDF.
///
/// The salt is the email **as the server knows it**: it compares character by
/// character. The hashes and the key are already computed with the new
/// parameters.
#[derive(Debug, Clone, Copy)]
pub struct KeyChange<'a> {
    pub salt: &'a str,
    pub kdf: KdfParams,
    /// The hash of the current password: the server checks with it that the
    /// owner is asking.
    pub current_hash: &'a str,
    pub new_hash: &'a str,
    /// The user key wrapped in the new master key.
    pub key: &'a str,
}

impl KeyChange<'_> {
    /// The new format: the same hash and the same wrapped key, but laid out
    /// in two objects with the salt and the KDF. At `/accounts/kdf`
    /// Vaultwarden accepts **only** this one; at `/accounts/password` both it
    /// and the old one. We send both at once: the server ignores extra
    /// fields.
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "masterPasswordHash": self.current_hash,
            "authenticationData": {
                "salt": self.salt,
                "kdf": self.kdf.json(),
                "masterPasswordAuthenticationHash": self.new_hash,
            },
            "unlockData": {
                "salt": self.salt,
                "kdf": self.kdf.json(),
                "masterKeyWrappedUserKey": self.key,
            },
            "newMasterPasswordHash": self.new_hash,
            "key": self.key,
        })
    }
}

/// Changing the master password.
pub async fn change_password(
    base_url: &str,
    access_token: &str,
    change: &KeyChange<'_>,
    hint: Option<&str>,
) -> anyhow::Result<()> {
    let mut body = change.json();
    body.as_object_mut().expect("an object").insert("masterPasswordHint".into(), serde_json::json!(hint));
    send(base_url, access_token, reqwest::Method::POST, "api/accounts/password", Some(body)).await?;
    Ok(())
}

/// Changing the KDF.
pub async fn change_kdf(base_url: &str, access_token: &str, change: &KeyChange<'_>) -> anyhow::Result<()> {
    let mut body = change.json();
    let obj = body.as_object_mut().expect("an object");
    // The old flat format, for servers that do not know the new one yet.
    obj.insert("kdf".into(), serde_json::json!(change.kdf.kdf));
    obj.insert("kdfIterations".into(), serde_json::json!(change.kdf.iterations));
    obj.insert("kdfMemory".into(), serde_json::json!(change.kdf.memory));
    obj.insert("kdfParallelism".into(), serde_json::json!(change.kdf.parallelism));
    send(base_url, access_token, reqwest::Method::POST, "api/accounts/kdf", Some(body)).await?;
    Ok(())
}

/// The first step of changing the email: the server sends a code to the new
/// address.
pub async fn email_token(
    base_url: &str,
    access_token: &str,
    hash: &str,
    new_email: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "masterPasswordHash": hash, "newEmail": new_email });
    send(base_url, access_token, reqwest::Method::POST, "api/accounts/email-token", Some(body)).await?;
    Ok(())
}

/// The second step: the code from the new address, with the hash and the key
/// already under the new salt.
pub async fn change_email(
    base_url: &str,
    access_token: &str,
    hash: &str,
    new_email: &str,
    new_hash: &str,
    token: &str,
    key: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({
        "masterPasswordHash": hash,
        "newEmail": new_email,
        "newMasterPasswordHash": new_hash,
        "token": token,
        "key": key,
    });
    send(base_url, access_token, reqwest::Method::POST, "api/accounts/email", Some(body)).await?;
    Ok(())
}

/// Resetting the security stamp: every device is logged out, ours among
/// them.
pub async fn deauthorize(base_url: &str, access_token: &str, hash: &str) -> anyhow::Result<()> {
    let body = serde_json::json!({ "masterPasswordHash": hash });
    send(base_url, access_token, reqwest::Method::POST, "api/accounts/security-stamp", Some(body)).await?;
    Ok(())
}

/// Deleting the account on the server.
pub async fn delete(base_url: &str, access_token: &str, hash: &str) -> anyhow::Result<()> {
    let body = serde_json::json!({ "masterPasswordHash": hash });
    send(base_url, access_token, reqwest::Method::POST, "api/accounts/delete", Some(body)).await?;
    Ok(())
}

/// Deleting every item and folder of one's own. Organisations are left
/// alone.
pub async fn purge(base_url: &str, access_token: &str, hash: &str) -> anyhow::Result<()> {
    let body = serde_json::json!({ "masterPasswordHash": hash });
    send(base_url, access_token, reqwest::Method::POST, "api/ciphers/purge", Some(body)).await?;
    Ok(())
}

// -- The second factor ------------------------------------------------------

pub async fn two_factor(base_url: &str, access_token: &str) -> anyhow::Result<Vec<TwoFactorProvider>> {
    let text = send(base_url, access_token, reqwest::Method::GET, "api/two-factor", None).await?;
    parse_two_factor(&text)
}

pub async fn authenticator(base_url: &str, access_token: &str, hash: &str) -> anyhow::Result<Authenticator> {
    let body = serde_json::json!({ "masterPasswordHash": hash });
    let text =
        send(base_url, access_token, reqwest::Method::POST, "api/two-factor/get-authenticator", Some(body)).await?;
    parse_authenticator(&text)
}

pub async fn enable_authenticator(
    base_url: &str,
    access_token: &str,
    hash: &str,
    key: &str,
    token: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "key": key, "token": token, "masterPasswordHash": hash });
    send(base_url, access_token, reqwest::Method::PUT, "api/two-factor/authenticator", Some(body)).await?;
    Ok(())
}

pub async fn email_two_factor(base_url: &str, access_token: &str, hash: &str) -> anyhow::Result<EmailTwoFactor> {
    let body = serde_json::json!({ "masterPasswordHash": hash });
    let text = send(base_url, access_token, reqwest::Method::POST, "api/two-factor/get-email", Some(body)).await?;
    parse_email_two_factor(&text)
}

pub async fn send_email_two_factor(
    base_url: &str,
    access_token: &str,
    hash: &str,
    email: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "email": email, "masterPasswordHash": hash });
    send(base_url, access_token, reqwest::Method::POST, "api/two-factor/send-email", Some(body)).await?;
    Ok(())
}

pub async fn enable_email_two_factor(
    base_url: &str,
    access_token: &str,
    hash: &str,
    email: &str,
    token: &str,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "email": email, "token": token, "masterPasswordHash": hash });
    send(base_url, access_token, reqwest::Method::PUT, "api/two-factor/email", Some(body)).await?;
    Ok(())
}

pub async fn disable_two_factor(
    base_url: &str,
    access_token: &str,
    hash: &str,
    provider: u8,
) -> anyhow::Result<()> {
    let body = serde_json::json!({ "type": provider, "masterPasswordHash": hash });
    send(base_url, access_token, reqwest::Method::PUT, "api/two-factor/disable", Some(body)).await?;
    Ok(())
}

/// The recovery code. `None` means the second factor was never turned on and
/// the account has no code yet.
pub async fn recovery_code(base_url: &str, access_token: &str, hash: &str) -> anyhow::Result<Option<String>> {
    let body = serde_json::json!({ "masterPasswordHash": hash });
    let text = send(base_url, access_token, reqwest::Method::POST, "api/two-factor/get-recover", Some(body)).await?;
    parse_recovery_code(&text)
}

// -- Devices ----------------------------------------------------------------

pub async fn devices(base_url: &str, access_token: &str) -> anyhow::Result<Vec<Device>> {
    let text = send(base_url, access_token, reqwest::Method::GET, "api/devices", None).await?;
    parse_devices(&text)
}

/// A server error turned into text one can act on.
///
/// A wrong master password comes back from the server as a 400 with the text
/// `Invalid password`. That is not a failure but the ordinary answer to a
/// typo, and the interface has to show exactly that, through a translation
/// key.
fn explain(status: reqwest::StatusCode, text: &str) -> anyhow::Error {
    let detail = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("Message"))
                .or_else(|| v.get("errorModel").and_then(|m| m.get("message")))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| text.chars().take(200).collect());
    if detail.to_lowercase().contains("invalid password") {
        return anyhow::anyhow!("err.badPassword");
    }
    anyhow::anyhow!("the server answered {status}: {detail}")
}

/// The shared wrapper around a request.
async fn send(
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
        return Err(explain(status, &text));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vaultwardens_profile_parses() {
        // The shape of `User::to_json` from Vaultwarden: no password hint
        // there, but keys and organisations we do not need.
        let raw = r##"{"_status":0,"id":"u1","name":"Someone","email":"k@example.com",
            "emailVerified":true,"premium":true,"premiumFromOrganization":false,"culture":"en-US",
            "twoFactorEnabled":false,"key":"2.a|b|c","privateKey":"2.d|e|f","securityStamp":"s",
            "organizations":[],"providers":[],"providerOrganizations":[],"forcePasswordReset":false,
            "avatarColor":"#175DDC","usesKeyConnector":false,"creationDate":"2024-01-02T03:04:05.000000Z",
            "object":"profile"}"##;
        let p = parse_profile(raw).expect("parses");
        assert_eq!(p.id, "u1");
        assert_eq!(p.email, "k@example.com");
        assert_eq!(p.name.as_deref(), Some("Someone"));
        assert_eq!(p.avatar_color.as_deref(), Some("#175DDC"));
        assert!(p.email_verified && p.premium && !p.two_factor_enabled);
        assert!(p.master_password_hint.is_none());
        assert_eq!(p.creation_date.as_deref(), Some("2024-01-02T03:04:05.000000Z"));
    }

    #[test]
    fn a_null_in_the_profile_is_not_an_error() {
        let p = parse_profile(r#"{"id":"u","email":"e","name":null,"avatarColor":null,
            "masterPasswordHint":null,"emailVerified":null,"twoFactorEnabled":null}"#)
            .expect("parses");
        assert!(p.name.is_none() && p.avatar_color.is_none() && !p.email_verified);
    }

    #[test]
    fn a_profile_that_is_not_an_object_is_an_error() {
        for raw in ["[]", "null", "\"ok\"", "42", "not json"] {
            assert!(parse_profile(raw).is_err(), "{raw} must not parse");
        }
    }

    #[test]
    fn the_list_of_second_factors() {
        // `TwoFactor::to_json_provider`: enabled and type, nothing else.
        let raw = r#"{"data":[{"enabled":true,"type":0,"object":"twoFactorProvider"},
            {"enabled":true,"type":7,"object":"twoFactorProvider"}],"object":"list","continuationToken":null}"#;
        let list = parse_two_factor(raw).expect("parses");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].kind, 0);
        assert_eq!(list[1].kind, 7);
        assert!(list.iter().all(|p| p.enabled));
    }

    #[test]
    fn an_empty_list_of_second_factors() {
        assert!(parse_two_factor(r#"{"data":[],"object":"list"}"#).expect("parses").is_empty());
        assert!(parse_two_factor(r#"{"data":null}"#).expect("parses").is_empty());
    }

    #[test]
    fn the_authenticator_secret() {
        let a = parse_authenticator(r#"{"enabled":false,"key":"JBSWY3DPEHPK3PXP","object":"twoFactorAuthenticator"}"#)
            .expect("parses");
        assert_eq!(a.key, "JBSWY3DPEHPK3PXP");
        assert!(!a.enabled);
        assert!(parse_authenticator(r#"{"enabled":false,"key":""}"#).is_err(), "an empty secret is a refusal");
        assert!(!format!("{a:?}").contains("JBSWY3DPEHPK3PXP"), "the secret leaked into Debug");
    }

    #[test]
    fn the_second_factor_email_with_a_boolean_and_a_string() {
        // On a read `enabled` is a boolean; after it is turned on Vaultwarden
        // sends a string.
        let read = parse_email_two_factor(r#"{"email":"k@example.com","enabled":true,"object":"twoFactorEmail"}"#)
            .expect("parses");
        assert!(read.enabled);
        let enabled = parse_email_two_factor(r#"{"email":"k@example.com","enabled":"true"}"#).expect("parses");
        assert!(enabled.enabled);
        let off = parse_email_two_factor(r#"{"email":null,"enabled":false}"#).expect("parses");
        assert!(!off.enabled && off.email.is_none());
    }

    #[test]
    fn the_recovery_code_is_sometimes_empty() {
        assert_eq!(
            parse_recovery_code(r#"{"code":"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567","object":"twoFactorRecover"}"#)
                .expect("parses")
                .as_deref(),
            Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        );
        assert!(parse_recovery_code(r#"{"code":null}"#).expect("parses").is_none());
    }

    #[test]
    fn devices() {
        let raw = r#"{"data":[
            {"id":"d1","name":"MacBook","type":7,"identifier":"aaaa-bbbb","creationDate":"2026-01-01T00:00:00Z",
             "isTrusted":false,"devicePendingAuthRequest":null,"object":"device"},
            {"id":"d2","name":null,"type":14,"identifier":"cccc","creationDate":null}
        ],"continuationToken":null,"object":"list"}"#;
        let list = parse_devices(raw).expect("parses");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].kind_name(), "desktop");
        assert_eq!(list[0].identifier, "aaaa-bbbb");
        assert_eq!(list[1].kind_name(), "cli");
        assert!(list[1].name.is_none());
    }

    #[test]
    fn a_crooked_device_does_not_hide_the_others() {
        let raw = r#"{"data":[{"id":"a","type":"seven"},{"id":"b","type":8}]}"#;
        let list = parse_devices(raw).expect("parses");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "b");
    }

    #[test]
    fn a_wrong_password_turns_into_a_translation_key() {
        // The exact shape of `err!` from Vaultwarden.
        let body = r#"{"message":"Invalid password","validationErrors":{"":["Invalid password"]},
            "errorModel":{"message":"Invalid password","object":"error"},"exceptionMessage":null,
            "exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"}"#;
        let err = explain(reqwest::StatusCode::BAD_REQUEST, body);
        assert_eq!(err.to_string(), "err.badPassword");

        let other = explain(reqwest::StatusCode::BAD_REQUEST, r#"{"message":"Email already in use"}"#);
        assert!(other.to_string().contains("Email already in use"));
    }

    #[test]
    fn the_key_change_body_holds_both_formats() {
        let kdf = KdfParams { kdf: 1, iterations: 3, memory: Some(64), parallelism: Some(4) };
        let body = KeyChange { salt: "k@example.com", kdf, current_hash: "old", new_hash: "hash", key: "2.key" }.json();
        assert_eq!(body["masterPasswordHash"], "old");
        assert_eq!(body["newMasterPasswordHash"], "hash");
        assert_eq!(body["key"], "2.key");
        assert_eq!(body["authenticationData"]["salt"], "k@example.com");
        assert_eq!(body["authenticationData"]["kdf"]["kdfType"], 1);
        assert_eq!(body["authenticationData"]["kdf"]["memory"], 64);
        assert_eq!(body["authenticationData"]["masterPasswordAuthenticationHash"], "hash");
        assert_eq!(body["unlockData"]["masterKeyWrappedUserKey"], "2.key");
        assert_eq!(body["unlockData"]["kdf"]["parallelism"], 4);
    }
}
