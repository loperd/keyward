//! Vaultwarden's admin panel over HTTP: `/admin` and what hangs under it.
//!
//! The panel is entered with the admin token: it is posted as a form, and the
//! server answers with a short-lived JWT in the `VW_ADMIN` cookie, which every
//! other request carries. Only the JSON endpoints are used; the overview and
//! diagnostics pages are HTML for a browser and are left alone.

use std::time::Duration;

use keyward_core::items::OrgRole;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const TIMEOUT: Duration = Duration::from_secs(20);
const COOKIE: &str = "VW_ADMIN";

/// Where the panel is: the server's address with `/admin`, https only — the
/// admin token and the session travel with every request.
pub fn panel_url(addr: &str) -> anyhow::Result<String> {
    let addr = addr.trim().trim_end_matches('/');
    if !addr.starts_with("https://") {
        return Err(keyward_core::fault!("err.vwadminHttps"));
    }
    Ok(if addr.ends_with("/admin") { addr.to_string() } else { format!("{addr}/admin") })
}

/// A session with the panel.
#[derive(Clone)]
pub struct Session {
    base: String,
    cookie: String,
    http: reqwest::Client,
}

fn client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        // The login answers with the page itself or a redirect to it; the
        // cookie is on the first answer, and following on would lose it.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| anyhow::anyhow!("the HTTP client will not build: {e}"))
}

/// Is this server a Vaultwarden with its admin panel switched on?
///
/// The server says what it is in `/api/config` — Vaultwarden answers with
/// `server.name`, Bitwarden's own servers with none — and `/admin` answers
/// 200 with its login page when an admin token is set, 404 when it is not.
pub async fn detect(server: &str) -> bool {
    let base = server.trim().trim_end_matches('/');
    if !base.starts_with("https://") {
        return false;
    }
    let Ok(http) = client() else { return false };
    let is_vaultwarden = match http.get(format!("{base}/api/config")).send().await {
        Ok(res) if res.status().is_success() => res
            .json::<Value>()
            .await
            .ok()
            .and_then(|v| v.pointer("/server/name").and_then(Value::as_str).map(|n| n.eq_ignore_ascii_case("vaultwarden")))
            .unwrap_or(false),
        _ => false,
    };
    if !is_vaultwarden {
        return false;
    }
    matches!(http.get(format!("{base}/admin")).send().await, Ok(res) if res.status().as_u16() == 200)
}

/// Enter the panel with the admin token.
pub async fn login(addr: &str, token: &str) -> anyhow::Result<Session> {
    let base = panel_url(addr)?;
    let http = client()?;
    let res = http
        .post(&base)
        .form(&[("token", token.trim())])
        .send()
        .await
        .map_err(|e| keyward_core::fault!("err.vwadminUnreachable", "reason" => e))?;
    match res.status().as_u16() {
        429 => return Err(keyward_core::fault!("err.vwadminRateLimited")),
        401 => return Err(keyward_core::fault!("err.vwadminBadToken")),
        404 => return Err(keyward_core::fault!("err.vwadminDisabled")),
        _ => {}
    }
    let cookie = res
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.split(';').next()?.trim().strip_prefix(&format!("{COOKIE}=")).map(str::to_string))
        .filter(|c| !c.is_empty())
        // A 200 with no cookie is the login page again: the token was wrong.
        .ok_or_else(|| keyward_core::fault!("err.vwadminBadToken"))?;
    Ok(Session { base, cookie, http })
}

/// The code of a refusal that means "the session ran out": the plugin logs in
/// again once on it.
pub const SESSION_EXPIRED: &str = "err.vwadminSession";

impl Session {
    async fn send(&self, req: reqwest::RequestBuilder) -> anyhow::Result<String> {
        let res = req
            .header(reqwest::header::COOKIE, format!("{COOKIE}={}", self.cookie))
            .send()
            .await
            .map_err(|e| keyward_core::fault!("err.vwadminUnreachable", "reason" => e))?;
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        if !status.is_success() {
            // Vaultwarden's errors are JSON with a message; anything else is
            // cut short rather than dumped whole.
            let message = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| text.chars().take(200).collect());
            if status.as_u16() == 401 {
                return Err(keyward_core::fault!(SESSION_EXPIRED));
            }
            return Err(keyward_core::fault!("err.vwadminRefused", "status" => status.as_u16(), "message" => message));
        }
        Ok(text)
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let text = self.send(self.http.get(format!("{}/{path}", self.base))).await?;
        serde_json::from_str(&text).map_err(|e| keyward_core::fault!("err.vwadminAnswer", "reason" => e))
    }

    async fn post(&self, path: &str, body: Value) -> anyhow::Result<String> {
        self.send(self.http.post(format!("{}/{path}", self.base)).json(&body)).await
    }

    pub async fn users(&self) -> anyhow::Result<Vec<User>> {
        self.get("users").await
    }

    pub async fn invite(&self, email: &str) -> anyhow::Result<()> {
        self.post("invite", serde_json::json!({ "email": email.trim() })).await.map(drop)
    }

    pub async fn act(&self, user_id: &str, action: UserAction) -> anyhow::Result<()> {
        self.post(&format!("users/{}/{}", checked_id(user_id)?, action.path()), Value::Null).await.map(drop)
    }

    pub async fn set_org_role(&self, user_id: &str, org_id: &str, role: OrgRole) -> anyhow::Result<()> {
        let code = role.code().ok_or_else(|| keyward_core::fault!("err.orgRoleNotYours"))?;
        self.post(
            "users/org_type",
            serde_json::json!({ "user_type": code.to_string(), "user_uuid": user_id, "org_uuid": org_id }),
        )
        .await
        .map(drop)
    }

    pub async fn delete_org(&self, org_id: &str) -> anyhow::Result<()> {
        self.post(&format!("organizations/{}/delete", checked_id(org_id)?), Value::Null).await.map(drop)
    }

    /// The server's settings, in its own groups, out of the settings page.
    pub async fn settings(&self) -> anyhow::Result<Vec<crate::settings::SettingsGroup>> {
        let html = self.send(self.http.get(self.base.clone())).await?;
        Ok(crate::settings::parse(&html))
    }

    /// Save the whole editable set — see `settings::to_save`.
    pub async fn save_settings(&self, body: Value) -> anyhow::Result<()> {
        self.post("config", body).await.map(drop)
    }

    /// Back to the defaults and what the environment says: the saved config
    /// is removed.
    pub async fn reset_settings(&self) -> anyhow::Result<()> {
        self.post("config/delete", Value::Null).await.map(drop)
    }

    pub async fn backup_db(&self) -> anyhow::Result<String> {
        self.post("config/backup_db", Value::Null).await
    }

    pub async fn test_smtp(&self, email: &str) -> anyhow::Result<()> {
        self.post("test/smtp", serde_json::json!({ "email": email.trim() })).await.map(drop)
    }
}

/// An identifier fit to go into a path.
fn checked_id(id: &str) -> anyhow::Result<&str> {
    if !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        Ok(id)
    } else {
        Err(keyward_core::fault!("err.vwadminBadId"))
    }
}

/// What can be done to a user from the panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserAction {
    ResendInvite,
    Disable,
    Enable,
    /// Log them out of every device.
    Deauth,
    RemoveTwoFactor,
    Delete,
}

impl UserAction {
    /// Cannot be undone, or locks a person out: drawn in red.
    pub fn danger(self) -> bool {
        matches!(self, Self::Delete | Self::RemoveTwoFactor)
    }

    /// Asked about before it is done: everything that cuts a person off.
    pub fn confirm(self) -> bool {
        matches!(self, Self::Delete | Self::RemoveTwoFactor | Self::Deauth | Self::Disable)
    }

    fn path(self) -> &'static str {
        match self {
            Self::ResendInvite => "invite/resend",
            Self::Disable => "disable",
            Self::Enable => "enable",
            Self::Deauth => "deauth",
            Self::RemoveTwoFactor => "remove-2fa",
            Self::Delete => "delete",
        }
    }
}

/// A user as the panel lists them. Only what is shown is parsed: the keys and
/// the security stamp the server sends along are left in the answer.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: String,
    #[serde(default, rename = "_status")]
    pub status: i32,
    #[serde(default)]
    pub user_enabled: Option<bool>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub two_factor_enabled: bool,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub last_active: Option<String>,
    /// Confirmed memberships.
    #[serde(default)]
    pub organizations: Vec<Membership>,
    /// Accepted and confirmed ones.
    #[serde(default)]
    pub organizations_new: Vec<Membership>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub kind: i32,
    #[serde(default)]
    pub status: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_panel_is_under_admin_and_https_only() {
        assert_eq!(panel_url("https://vw.example.com/").unwrap(), "https://vw.example.com/admin");
        assert_eq!(panel_url("https://vw.example.com/admin").unwrap(), "https://vw.example.com/admin");
        assert!(panel_url("http://vw.example.com").is_err());
    }

    #[test]
    fn a_user_is_read_without_their_keys() {
        let u: User = serde_json::from_str(
            r#"{"id":"u1","name":"A","email":"a@x","_status":0,"userEnabled":true,"twoFactorEnabled":true,
                "key":"secret","privateKey":"secret","lastActive":null,
                "organizations":[{"id":"o1","name":"Acme","type":0,"status":2}],"organizationsNew":[]}"#,
        )
        .unwrap();
        assert_eq!(u.organizations[0].kind, 0);
        assert!(u.two_factor_enabled && u.user_enabled == Some(true));
    }
}
