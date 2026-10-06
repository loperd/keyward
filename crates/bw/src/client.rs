//! The shared setup of the http client to Bitwarden.
//!
//! The headers here are no formality. Vaultwarden **hides items of newer
//! kinds** from a client that did not introduce itself with a recent enough
//! version: without `Bitwarden-Client-Version` the server quietly gives a vault
//! with no ssh keys — exactly what emptied the routes while the parsing looked
//! perfectly healthy.

use std::time::Duration;

/// The client name out of Bitwarden's list.
const CLIENT_NAME: &str = "desktop";

/// The version the client introduces itself with. Two servers read it: below
/// 2024.12 Vaultwarden hides the ssh keys from the answer, and bitwarden.com
/// refuses a login from a version it calls too old ("Please update your app
/// to continue using Bitwarden" — it refused 2024.12.0 in October 2026). It
/// follows the current desktop release; it must not be lowered.
const CLIENT_VERSION: &str = "2026.6.0";

/// `DeviceType.MacOsDesktop` in Bitwarden's classification.
const DEVICE_TYPE: &str = "7";

pub fn build(timeout: Duration) -> anyhow::Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("Bitwarden-Client-Name", reqwest::header::HeaderValue::from_static(CLIENT_NAME));
    headers.insert(
        "Bitwarden-Client-Version",
        reqwest::header::HeaderValue::from_static(CLIENT_VERSION),
    );
    headers.insert("Device-Type", reqwest::header::HeaderValue::from_static(DEVICE_TYPE));

    reqwest::Client::builder()
        .timeout(timeout)
        .default_headers(headers)
        .user_agent(concat!("keyward/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| anyhow::anyhow!("the http client will not build: {e}"))
}

/// Does this look like an item identifier rather than a piece of a path?
///
/// The identifier goes straight into the request path, and `Url` normalises
/// `..` before sending: `/api/ciphers/../../foo` leaves for the server as
/// `/foo`, with our bearer token in the header. `?` and `#` cut the tail of the
/// path off just as well. The server issues identifiers itself and they are
/// always UUIDs, so the check cuts nothing real away.
pub fn is_path_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_identifiers_pass() {
        assert!(is_path_id("6f4b2c1e-9a3d-4c7b-8e21-0f5a6b7c8d9e"));
        assert!(is_path_id("abcDEF012"));
        assert!(is_path_id("a_b-c"));
    }

    #[test]
    fn a_piece_of_a_path_does_not_count_as_an_identifier() {
        for bad in [
            "",
            "..",
            "../../api/accounts",
            "a/b",
            "a?query=1",
            "a#fragment",
            "a b",
            "a%2fb",
            // Not ASCII: the check must not let a letter with a
            // diacritic through either.
            "hôte",
            "https://evil.example.com/",
            &"a".repeat(65),
        ] {
            assert!(!is_path_id(bad), "accepted: {bad:?}");
        }
    }

    #[test]
    fn dots_in_a_path_are_normalised_before_sending() {
        // What it is all for: showing that the substitution does not stay
        // inside `/api/ciphers/` but genuinely walks the request off to another
        // endpoint.
        let url = format!("https://server.example/api/ciphers/{}/delete", "../../identity/connect/token");
        let req = reqwest::Client::new().put(url).build().expect("the request builds");
        assert_eq!(req.url().path(), "/identity/connect/token/delete");
    }
}
