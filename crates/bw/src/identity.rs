//! A session's tokens: the access token runs out within hours, the refresh
//! token gets a new one.
//!
//! Vaultwarden (1.33 and on) signs a refresh token for thirty days and hands
//! out a **new** one with every refresh. A client that keeps the first one
//! signs itself out on the thirtieth day: rbw's own refresh reads the access
//! token alone and drops the new refresh token, and keyward kept syncing on the
//! token it logged in with until the server said `invalid_grant` — which rbw,
//! reading the body without looking at the status, reported as "failed to
//! parse JSON". So the refresh is ours: the status is read, the new refresh
//! token is kept, and a session the server has ended is said in words.

use std::time::Duration;

use base64::Engine as _;
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(30);

/// What a refresh brings back.
pub struct Tokens {
    pub access_token: Zeroizing<String>,
    /// The new refresh token, when the server rotates them — it must replace
    /// the old one, or the session ends on the old one's date.
    pub refresh_token: Option<Zeroizing<String>>,
}

/// The identity server of an account, as rbw finds it: the one set on the
/// account, Bitwarden's own for its clouds, `<server>/identity` for a
/// self-hosted one.
pub fn url(base_url: &str, explicit: Option<&str>) -> String {
    if let Some(u) = explicit.map(str::trim).filter(|u| !u.is_empty()) {
        return u.trim_end_matches('/').to_string();
    }
    let base = base_url.trim().trim_end_matches('/');
    match base {
        "" | "https://api.bitwarden.com" => "https://identity.bitwarden.com".to_string(),
        "https://api.bitwarden.eu" => "https://identity.bitwarden.eu".to_string(),
        _ => format!("{base}/identity"),
    }
}

/// Whether an access token is spent, or will be within `margin` seconds, by
/// its own `exp`. A token whose `exp` cannot be read counts as spent: a refresh
/// costs one request, a stale token a failed sync.
pub fn spent(access_token: &str, now: u64, margin: u64) -> bool {
    let exp = access_token
        .split('.')
        .nth(1)
        .and_then(|p| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p.trim_end_matches('=')).ok())
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|claims| claims.get("exp").and_then(serde_json::Value::as_u64));
    exp.is_none_or(|exp| exp <= now + margin)
}

/// Trades the refresh token for new tokens.
pub async fn refresh(identity_url: &str, refresh_token: &str) -> anyhow::Result<Tokens> {
    let http = crate::client::build(TIMEOUT)?;
    let form = [("grant_type", "refresh_token"), ("client_id", "cli"), ("refresh_token", refresh_token)];
    let res = http
        .post(format!("{}/connect/token", identity_url.trim_end_matches('/')))
        .form(&form)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("the server is unreachable: {e}"))?;
    let status = res.status().as_u16();
    let body = Zeroizing::new(res.text().await.map_err(|e| anyhow::anyhow!("the token answer did not arrive: {e}"))?);
    read_answer(status, &body)
}

/// The token endpoint's answer, read by its status first.
pub fn read_answer(status: u16, body: &str) -> anyhow::Result<Tokens> {
    if !(200..300).contains(&status) {
        // `invalid_grant` is how Bitwarden's servers say a refresh token is
        // no good any more: expired, or its device signed out. Nothing but a
        // new login brings the session back.
        let error = serde_json::from_str::<serde_json::Value>(body).ok().and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string));
        if error.as_deref() == Some("invalid_grant") {
            anyhow::bail!("err.sessionEnded");
        }
        // The error answer carries no secret: its words are said as they are.
        anyhow::bail!("the token server answered {status}: {}", body.chars().take(200).collect::<String>());
    }
    #[derive(serde::Deserialize)]
    struct Answer {
        access_token: String,
        #[serde(default)]
        refresh_token: Option<String>,
    }
    let a: Answer = serde_json::from_str(body).map_err(|e| anyhow::anyhow!("the token answer will not parse: {}", e.classify_word()))?;
    if a.access_token.is_empty() {
        anyhow::bail!("the token answer will not parse: it has no access token");
    }
    Ok(Tokens { access_token: Zeroizing::new(a.access_token), refresh_token: a.refresh_token.filter(|r| !r.is_empty()).map(Zeroizing::new) })
}

/// A parse error by its kind and place only: the answer holds tokens, and its
/// text stays out of messages.
trait ClassifyWord {
    fn classify_word(&self) -> String;
}

impl ClassifyWord for serde_json::Error {
    fn classify_word(&self) -> String {
        format!("{:?} at line {} column {}", self.classify(), self.line(), self.column())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(claims: serde_json::Value) -> String {
        let e = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        format!("{}.{}.sig", e(br#"{"alg":"RS256"}"#), e(claims.to_string().as_bytes()))
    }

    #[test]
    fn an_access_token_is_spent_by_its_own_date() {
        let t = jwt(serde_json::json!({ "exp": 1000 }));
        assert!(!spent(&t, 900, 60));
        assert!(spent(&t, 950, 60), "within the margin");
        assert!(spent(&t, 1001, 0));
        assert!(spent("not-a-jwt", 0, 0), "an unreadable token is refreshed rather than trusted");
    }

    #[test]
    fn the_rotated_refresh_token_comes_back() {
        let t = read_answer(200, r#"{"access_token":"a2","refresh_token":"r2","expires_in":7200,"token_type":"Bearer"}"#).unwrap();
        assert_eq!(t.access_token.as_str(), "a2");
        assert_eq!(t.refresh_token.as_deref().map(String::as_str), Some("r2"));
        let t = read_answer(200, r#"{"access_token":"a2"}"#).unwrap();
        assert!(t.refresh_token.is_none(), "a server that does not rotate keeps the old one");
    }

    /// The answer that broke syncing on the thirtieth day: Vaultwarden's own
    /// words for an expired refresh token, with a 400.
    #[test]
    fn an_ended_session_is_said_as_such_not_as_a_parse_error() {
        let e = read_answer(400, r#"{"error":"invalid_grant"}"#).err().unwrap();
        assert_eq!(e.to_string(), "err.sessionEnded");
        let e = read_answer(500, "boom").err().unwrap();
        assert!(e.to_string().contains("500"), "{e}");
        let e = read_answer(200, r#"{"error":"invalid_grant"}"#).err().unwrap();
        assert!(e.to_string().contains("will not parse") && !e.to_string().contains("invalid_grant"), "{e}");
    }

    #[test]
    fn the_identity_server_is_found_as_rbw_finds_it() {
        assert_eq!(url("https://vw.example.net/", None), "https://vw.example.net/identity");
        assert_eq!(url("https://vw.example.net", Some("https://id.example.net/")), "https://id.example.net");
        assert_eq!(url("https://api.bitwarden.eu", None), "https://identity.bitwarden.eu");
        assert_eq!(url("", None), "https://identity.bitwarden.com");
    }
}
