//! Syncing: we fetch `/api/sync` ourselves.

use std::time::Duration;

use crate::model::Sync;

const TIMEOUT: Duration = Duration::from_secs(30);

/// Fetches the whole snapshot of the vault.
///
/// Everything the server sent comes back, deleted items and named
/// organisations included: deciding what to show belongs to the interface, not
/// to the transport.
pub async fn fetch(base_url: &str, access_token: &str) -> anyhow::Result<Sync> {
    let http = crate::client::build(TIMEOUT)?;

    let url = format!("{}/api/sync?excludeDomains=true", base_url.trim_end_matches('/'));
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
    if !status.is_success() {
        anyhow::bail!("the server answered {status}: {}", body.chars().take(200).collect::<String>());
    }

    parse(&body)
}

/// Parsing the answer apart from making the request, so that it can be tested
/// without bringing a server up.
///
/// The "is this an object" check is no nitpick: every field of `Sync` has a
/// default, so `[]`, `"ok"` and `42` parsed into an **empty vault** — and at
/// once wrote themselves over a good snapshot on disk. Only this check tells
/// an empty vault from somebody else's answer.
pub fn parse(body: &str) -> anyhow::Result<Sync> {
    if !body.trim_start().starts_with('{') {
        anyhow::bail!("the sync answer will not parse: it is not an object");
    }
    serde_json::from_str(body).map_err(|e| anyhow::anyhow!("the sync answer will not parse: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_that_is_not_an_object_is_refused() {
        // Every field of `Sync` has a default, so an answer like this parsed
        // into an empty vault, and the empty vault went straight to disk over
        // the real one. The catalogue emptied and the ssh agent lost every
        // key.
        for body in ["[]", "null", "\"ok\"", "42", "true"] {
            let err = parse(body).expect_err("an answer like that cannot be a sync");
            assert!(err.to_string().contains("will not parse"), "{body}: {err}");
        }
    }

    #[test]
    fn a_cut_or_rubbish_answer_is_an_error() {
        for body in ["", "{", r#"{"ciphers":[{"id":"1"}"#, "<html>502</html>"] {
            assert!(parse(body).is_err(), "{body:?} must not parse");
        }
    }

    #[test]
    fn a_real_answer_parses() {
        let s = parse(r#"{"profile":{"id":"p"},"ciphers":[{"id":"1","name":"n"}]}"#).expect("parsed");
        assert_eq!(s.profile.id, "p");
        assert_eq!(s.ciphers.len(), 1);
    }

    #[test]
    fn an_empty_vault_is_not_an_error() {
        assert!(parse("{}").expect("parsed").ciphers.is_empty());
    }
}
