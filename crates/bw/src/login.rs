//! Logging in: the KDF the account uses, the password trade for tokens, the
//! second factor.
//!
//! Every answer is read by its status first. rbw read the body as the answer it
//! hoped for whatever the status, so a refusal — a wrong password, a second
//! factor the server asks for, a rate limit — came out as "failed to parse
//! JSON". Here each has its own word.
//!
//! The shapes are Vaultwarden's (1.37) and Bitwarden's: Vaultwarden refuses a
//! password with an error model (`"error": ""`, the words in `errorModel`),
//! Bitwarden with `invalid_grant` / `invalid_username_or_password`; both ask
//! for a second factor with `"Two factor required."` and the providers' ids.

use std::time::Duration;

use base64::Engine as _;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::crypto::Kdf;

const TIMEOUT: Duration = Duration::from_secs(30);

/// This device, as the server lists it. The identifier is what makes it the
/// same device across logins: a new one is a "new device" to the server, with
/// an email about it.
pub struct Device<'a> {
    pub id: &'a str,
    pub name: &'a str,
    /// Bitwarden's `DeviceType`. rbw sent 8, and the server keeps the device
    /// it registered: the same is sent so that it stays one device.
    pub kind: u32,
}

/// The device type rbw registered keyward's device with.
pub const DEVICE_KIND: u32 = 8;

/// The name the device goes by in the account's list of devices.
pub const DEVICE_NAME: &str = "keyward";

/// What a password login comes to.
pub enum Answer {
    Done {
        access_token: Zeroizing<String>,
        refresh_token: Zeroizing<String>,
        /// The protected user key (`Key`), encrypted with the master key.
        key: String,
        /// The protected private key, when the answer has it.
        private_key: Option<String>,
        /// The token that stands in for the second factor on this device
        /// next time (`TwoFactorToken`): the server sends it only when the
        /// code came with `twoFactorRemember=1`.
        remember_token: Option<Zeroizing<String>>,
    },
    /// The server wants a second factor: the providers it offers, by
    /// Bitwarden's ids, and the session token an email code is asked with.
    TwoFactor { providers: Vec<u8>, session_token: Option<String> },
    /// bitwarden.com has not seen this device: it mailed a code, and the
    /// login is made again with it (`newDeviceOtp`). Accounts with a second
    /// factor are not asked.
    NewDevice,
}

fn auth_email(email: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(email.as_bytes())
}

/// The account's KDF, asked before the password can be hashed.
pub async fn prelogin(identity_url: &str, email: &str) -> anyhow::Result<Kdf> {
    let http = crate::client::build(TIMEOUT)?;
    let res = http
        .post(format!("{}/accounts/prelogin", identity_url.trim_end_matches('/')))
        .json(&serde_json::json!({ "email": email }))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("the server is unreachable: {e}"))?;
    let status = res.status().as_u16();
    let body = res.text().await.map_err(|e| anyhow::anyhow!("the prelogin answer did not arrive: {e}"))?;
    read_prelogin(status, &body)
}

/// A field by either spelling: Vaultwarden writes camelCase, older servers
/// PascalCase.
fn field<'a>(v: &'a Value, camel: &str) -> Option<&'a Value> {
    let mut pascal = camel.to_string();
    if let Some(first) = pascal.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    v.get(camel).or_else(|| v.get(&pascal)).filter(|x| !x.is_null())
}

fn number(v: &Value, camel: &str) -> Option<u32> {
    field(v, camel).and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok()))).and_then(|n| u32::try_from(n).ok())
}

pub fn read_prelogin(status: u16, body: &str) -> anyhow::Result<Kdf> {
    refusal(status, body, false)?;
    let v = object(body, "prelogin")?;
    let iterations = number(&v, "kdfIterations").ok_or_else(|| anyhow::anyhow!("err.loginFailed {}", reason("the prelogin answer has no KDF iterations")))?;
    let kdf = match number(&v, "kdf") {
        Some(0) => Kdf::Pbkdf2 { iterations },
        // Argon2's memory and lanes are the account's own: a default in their
        // place derives another key and refuses a right password.
        Some(1) => Kdf::Argon2id {
            iterations,
            memory_mib: number(&v, "kdfMemory").ok_or_else(|| anyhow::anyhow!("err.loginFailed {}", reason("the prelogin answer has no Argon2 memory")))?,
            parallelism: number(&v, "kdfParallelism").ok_or_else(|| anyhow::anyhow!("err.loginFailed {}", reason("the prelogin answer has no Argon2 parallelism")))?,
        },
        other => anyhow::bail!("err.loginFailed {}", reason(&format!("an unknown KDF: {other:?}"))),
    };
    // The server picks the work the password hash it receives costs: too
    // little and it can brute-force the password, too much and the daemon
    // hangs. Refused before the password is derived at all.
    Ok(kdf.checked()?)
}

/// Bitwarden's provider id for a remembered device: the token from an earlier
/// login's `TwoFactorToken` goes in place of a code.
pub const REMEMBER: u8 = 5;

/// The second factor a login carries.
#[derive(Clone, Copy)]
pub enum SecondFactor<'a> {
    /// A code typed now. `remember` asks the server for a token that stands
    /// in for the second factor on this device the next time.
    Code { provider: u8, token: &'a str, remember: bool },
    /// The token a server handed out when it remembered this device. A server
    /// that no longer takes it asks for the second factor as if none were
    /// sent: that is a `TwoFactor` answer, not a wrong code.
    Remembered(&'a str),
}

/// Trades the password hash (and a second factor) for tokens.
pub async fn login(
    identity_url: &str,
    email: &str,
    password_hash: &str,
    device: &Device<'_>,
    second: Option<SecondFactor<'_>>,
    new_device_code: Option<&str>,
) -> anyhow::Result<Answer> {
    let http = crate::client::build(TIMEOUT)?;
    let kind = device.kind.to_string();
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "password"),
        ("scope", "api offline_access"),
        ("client_id", "cli"),
        ("username", email),
        ("password", password_hash),
        ("deviceType", &kind),
        ("deviceIdentifier", device.id),
        ("deviceName", device.name),
        ("devicePushToken", ""),
    ];
    let provider;
    match second {
        Some(SecondFactor::Code { provider: p, token, remember }) => {
            provider = p.to_string();
            form.push(("twoFactorProvider", &provider));
            form.push(("twoFactorToken", token));
            form.push(("twoFactorRemember", if remember { "1" } else { "0" }));
        }
        Some(SecondFactor::Remembered(token)) => {
            provider = REMEMBER.to_string();
            form.push(("twoFactorProvider", &provider));
            form.push(("twoFactorToken", token));
            form.push(("twoFactorRemember", "0"));
        }
        None => {}
    }
    if let Some(code) = new_device_code {
        form.push(("newDeviceOtp", code));
    }
    let res = http
        .post(format!("{}/connect/token", identity_url.trim_end_matches('/')))
        .header("auth-email", auth_email(email))
        .form(&form)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("the server is unreachable: {e}"))?;
    let status = res.status().as_u16();
    let body = Zeroizing::new(res.text().await.map_err(|e| anyhow::anyhow!("the login answer did not arrive: {e}"))?);
    // A remembered device's token is no typed code: a refusal of it is the
    // server asking for the second factor again.
    let typed = matches!(second, Some(SecondFactor::Code { .. }));
    read_login(status, &body, typed || new_device_code.is_some())
}

/// The login's answer. `with_code`: a second factor's code was sent, so a
/// refusal is the code's.
pub fn read_login(status: u16, body: &str, with_code: bool) -> anyhow::Result<Answer> {
    if !(200..300).contains(&status) {
        match device_check(body) {
            Some(DeviceCheck::Required) if !with_code => return Ok(Answer::NewDevice),
            Some(DeviceCheck::Required | DeviceCheck::WrongCode) => anyhow::bail!("err.badNewDeviceCode"),
            None => {}
        }
        if let Some(two_factor) = two_factor_asked(body) {
            // Asked again after a code was sent: the code was wrong.
            if with_code {
                anyhow::bail!("err.badTwoFactor");
            }
            return Ok(two_factor);
        }
        refusal(status, body, with_code)?;
        anyhow::bail!("err.loginFailed {}", reason(&format!("the server answered {status}")));
    }
    let v = object(body, "login")?;
    let text = |name: &str| field(&v, name).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    let (Some(access), Some(refresh), Some(key)) = (text("access_token"), text("refresh_token"), text("key")) else {
        anyhow::bail!("err.loginFailed {}", reason("the login answer lacks a token or the key"));
    };
    let remember_token = text("twoFactorToken").map(Zeroizing::new);
    Ok(Answer::Done { access_token: Zeroizing::new(access), refresh_token: Zeroizing::new(refresh), key, private_key: text("privateKey"), remember_token })
}

enum DeviceCheck {
    Required,
    WrongCode,
}

/// Bitwarden's device check, by the words its server sends — the server's
/// own comment calls them the flow's contract with the clients.
fn device_check(body: &str) -> Option<DeviceCheck> {
    let v: Value = serde_json::from_str(body).ok()?;
    let words = [
        v.get("error_description").and_then(Value::as_str),
        field(&v, "errorModel").and_then(|m| field(m, "message")).and_then(Value::as_str),
    ];
    let said = |w: &str| words.iter().flatten().any(|x| x.to_ascii_lowercase() == w);
    if said("new device verification required") {
        Some(DeviceCheck::Required)
    } else if said("invalid new device otp") {
        Some(DeviceCheck::WrongCode)
    } else {
        None
    }
}

/// Asks bitwarden.com to mail the device check's code again. It mails one on
/// its own the first time; the password hash proves it is the same login.
pub async fn resend_new_device_code(base_url: &str, email: &str, password_hash: &str) -> anyhow::Result<()> {
    let http = crate::client::build(TIMEOUT)?;
    let res = http
        .post(format!("{}/api/accounts/resend-new-device-otp", base_url.trim_end_matches('/')))
        .json(&serde_json::json!({ "email": email, "masterPasswordHash": password_hash }))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("the server is unreachable: {e}"))?;
    let status = res.status().as_u16();
    let body = res.text().await.unwrap_or_default();
    refusal(status, &body, false)
}

/// The second factor the answer asks for, if that is what it is.
fn two_factor_asked(body: &str) -> Option<Answer> {
    let v: Value = serde_json::from_str(body).ok()?;
    let providers = field(&v, "twoFactorProviders")?.as_array()?;
    let providers: Vec<u8> = providers
        .iter()
        .filter_map(|p| p.as_u64().map(|n| n as u8).or_else(|| p.as_str().and_then(|s| s.parse().ok())))
        .collect();
    let session_token = field(&v, "ssoEmail2faSessionToken").and_then(Value::as_str).map(str::to_string);
    Some(Answer::TwoFactor { providers, session_token })
}

/// A refusal, in our words. `Ok` when the status is a success.
fn refusal(status: u16, body: &str, with_code: bool) -> anyhow::Result<()> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    if status == 429 {
        anyhow::bail!("err.loginRateLimited");
    }
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let description = v.get("error_description").and_then(Value::as_str).unwrap_or("");
    // The server's own words: an error answer carries no secret.
    let message = field(&v, "errorModel")
        .and_then(|m| field(m, "message"))
        .or_else(|| field(&v, "message"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let wrong_password = description == "invalid_username_or_password" || message.starts_with("Username or password is incorrect");
    if wrong_password {
        anyhow::bail!("err.badPassword");
    }
    if with_code && status == 400 {
        anyhow::bail!("err.badTwoFactor");
    }
    if !message.is_empty() {
        anyhow::bail!("err.loginRefused {}", serde_json::json!({ "message": message.chars().take(200).collect::<String>() }));
    }
    anyhow::bail!("err.loginFailed {}", reason(&format!("the server answered {status}")))
}

fn object(body: &str, what: &str) -> anyhow::Result<Value> {
    let v: Value = serde_json::from_str(body).map_err(|e| {
        anyhow::anyhow!("err.loginFailed {}", reason(&format!("the {what} answer will not parse: {:?} at line {} column {}", e.classify(), e.line(), e.column())))
    })?;
    if !v.is_object() {
        anyhow::bail!("err.loginFailed {}", reason(&format!("the {what} answer is not an object")));
    }
    Ok(v)
}

fn reason(text: &str) -> String {
    serde_json::json!({ "reason": text }).to_string()
}

/// Asks for a code by email. Vaultwarden (1.37) sends it only to someone who
/// proves the password again — the hash goes along; rbw sent none, and the
/// server refused.
pub async fn send_two_factor_email(base_url: &str, email: &str, password_hash: &str, device_id: &str) -> anyhow::Result<()> {
    let http = crate::client::build(TIMEOUT)?;
    let res = http
        .post(format!("{}/api/two-factor/send-email-login", base_url.trim_end_matches('/')))
        .header("auth-email", auth_email(email))
        .json(&serde_json::json!({ "email": email, "masterPasswordHash": password_hash, "deviceIdentifier": device_id }))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("the server is unreachable: {e}"))?;
    let status = res.status().as_u16();
    let body = res.text().await.unwrap_or_default();
    refusal(status, &body, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(r: anyhow::Result<impl Sized>) -> String {
        r.err().map(|e| e.to_string()).unwrap_or_default()
    }

    #[test]
    fn the_kdf_comes_in_either_spelling() {
        assert!(matches!(read_prelogin(200, r#"{"kdf":0,"kdfIterations":600000,"kdfMemory":null}"#).unwrap(), Kdf::Pbkdf2 { iterations: 600_000 }));
        assert!(matches!(
            read_prelogin(200, r#"{"Kdf":1,"KdfIterations":3,"KdfMemory":64,"KdfParallelism":4}"#).unwrap(),
            Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 }
        ));
        assert!(err(read_prelogin(200, r#"{"kdf":1,"kdfIterations":3}"#)).contains("Argon2 memory"), "no default for an account's own parameters");
        assert_eq!(err(read_prelogin(429, "Too many requests")), "err.loginRateLimited");
    }

    #[test]
    fn a_prelogin_outside_the_bounds_is_refused() {
        for body in [
            r#"{"kdf":0,"kdfIterations":1}"#,
            r#"{"kdf":0,"kdfIterations":4000000000}"#,
            r#"{"kdf":1,"kdfIterations":1,"kdfMemory":64,"kdfParallelism":4}"#,
            r#"{"kdf":1,"kdfIterations":3,"kdfMemory":1,"kdfParallelism":4}"#,
            r#"{"kdf":1,"kdfIterations":3,"kdfMemory":1048576,"kdfParallelism":4}"#,
            r#"{"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":255}"#,
        ] {
            let e = read_prelogin(200, body).unwrap_err();
            assert!(e.downcast_ref::<crate::crypto::KdfOutOfRange>().is_some(), "{body}: {e}");
            assert_eq!(e.to_string(), crate::crypto::KDF_OUT_OF_RANGE);
        }
    }

    /// bitwarden.com's answers to a login from a device it has not seen, as
    /// its DeviceValidator words them.
    #[test]
    fn a_new_device_is_asked_for_its_code() {
        let required = r#"{"error":"invalid_grant","error_description":"New device verification required","ErrorModel":{"Message":"new device verification required","Object":"error"}}"#;
        assert!(matches!(read_login(400, required, false).unwrap(), Answer::NewDevice));
        let wrong = r#"{"error":"invalid_grant","error_description":"Invalid New Device OTP","ErrorModel":{"Message":"invalid new device otp","Object":"error"}}"#;
        assert_eq!(err(read_login(400, wrong, true)), "err.badNewDeviceCode");
        assert_eq!(err(read_login(400, required, true)), "err.badNewDeviceCode", "asked again after a code: the code did not take");
    }

    #[test]
    fn a_refusal_says_what_it_is() {
        // Vaultwarden's wrong password: an error model, `error` empty.
        let vw = r#"{"message":"Username or password is incorrect. Try again","errorModel":{"message":"Username or password is incorrect. Try again","object":"error"},"error":"","error_description":""}"#;
        assert_eq!(err(read_login(400, vw, false)), "err.badPassword");
        // Bitwarden's.
        let bw = r#"{"error":"invalid_grant","error_description":"invalid_username_or_password","ErrorModel":{"Message":"Username or password is incorrect. Try again."}}"#;
        assert_eq!(err(read_login(400, bw, false)), "err.badPassword");
        assert_eq!(err(read_login(429, r#"{"message":"Too many login requests"}"#, false)), "err.loginRateLimited");
        assert!(err(read_login(500, "", false)).starts_with("err.loginFailed"));
        let other = r#"{"message":"Email 2FA is disabled","errorModel":{"message":"Email 2FA is disabled"}}"#;
        assert!(err(read_login(400, other, false)).starts_with("err.loginRefused"), "the server's own words");
    }

    #[test]
    fn a_second_factor_is_asked_with_its_providers() {
        let body = r#"{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":["0","1"],"TwoFactorProviders2":{"0":null,"1":{"Email":"b***@x"}}}"#;
        let Answer::TwoFactor { providers, .. } = read_login(400, body, false).unwrap() else { panic!("a second factor") };
        assert_eq!(providers, vec![0, 1]);
        assert_eq!(err(read_login(400, body, true)), "err.badTwoFactor", "asked again after a code: the code was wrong");
    }

    #[test]
    fn a_remembered_device_brings_its_token_in_either_spelling() {
        for body in [
            r#"{"access_token":"a","refresh_token":"r","Key":"2.k|v|m","TwoFactorToken":"remember-me"}"#,
            r#"{"access_token":"a","refresh_token":"r","key":"2.k|v|m","twoFactorToken":"remember-me"}"#,
        ] {
            let Answer::Done { remember_token, .. } = read_login(200, body, true).unwrap() else { panic!("done") };
            assert_eq!(remember_token.as_deref().map(String::as_str), Some("remember-me"));
        }
    }

    #[test]
    fn a_login_brings_the_tokens_and_the_key() {
        let body = r#"{"access_token":"a","refresh_token":"r","Key":"2.k|v|m","PrivateKey":"2.p|v|m","Kdf":0}"#;
        let Answer::Done { access_token, refresh_token, key, private_key, remember_token } = read_login(200, body, false).unwrap() else { panic!("done") };
        assert_eq!((access_token.as_str(), refresh_token.as_str(), key.as_str()), ("a", "r", "2.k|v|m"));
        assert_eq!(private_key.as_deref(), Some("2.p|v|m"));
        assert!(remember_token.is_none(), "no token unless the device was remembered");
        assert!(err(read_login(200, r#"{"access_token":"a"}"#, false)).starts_with("err.loginFailed"));
        assert!(!err(read_login(200, "not json", false)).contains("not json"), "an answer's text stays out of the error");
    }
}
