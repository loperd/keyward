//! The client's half of WebAuthn, done in the daemon rather than trusted to
//! whoever asks.
//!
//! A browser normally checks that a page may speak for its `rpId` and writes
//! the client data itself. Here the request comes through an extension and a
//! bridge, and neither is taken at its word: the daemon parses the origin,
//! decides whether the site may claim the `rpId`, and builds `clientDataJSON`
//! byte for byte. What gets signed is therefore always "this origin, this
//! challenge" — a page cannot slip another site's name into a signature.

use sha2::{Digest as _, Sha256};

/// A page's origin, as far as WebAuthn cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// `https://host[:port]`, lowercase, punycode: what goes into the client
    /// data.
    pub serialized: String,
    pub host: String,
    /// The host is an address rather than a name: no suffix of it is a site.
    pub is_ip: bool,
}

/// The longest challenge taken. The spec asks for at least sixteen random
/// bytes; nothing honest sends kilobytes.
const CHALLENGE_MAX: usize = 1024;
const CHALLENGE_MIN: usize = 16;

fn bad_origin() -> anyhow::Error {
    keyward_core::fault!("err.passkeyBadOrigin")
}

/// Parses an origin. Only a secure context is accepted: `https`, or `http` on
/// `localhost` for a developer's own machine — the same line browsers draw.
pub fn origin(text: &str) -> anyhow::Result<Origin> {
    let url = reqwest::Url::parse(text.trim()).map_err(|_| bad_origin())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(bad_origin());
    }
    let host = url.host().ok_or_else(bad_origin)?;
    let (name, is_ip) = match host {
        url::Host::Domain(d) => (d.trim_end_matches('.').to_ascii_lowercase(), false),
        url::Host::Ipv4(a) => (a.to_string(), true),
        url::Host::Ipv6(a) => (format!("[{a}]"), true),
    };
    if name.is_empty() {
        return Err(bad_origin());
    }
    let local = name == "localhost" || name.ends_with(".localhost");
    match url.scheme() {
        "https" => {}
        "http" if local => {}
        _ => return Err(keyward_core::fault!("err.passkeyInsecureOrigin")),
    }
    let serialized = url.origin().ascii_serialization();
    if serialized == "null" {
        return Err(bad_origin());
    }
    Ok(Origin { serialized, host: name, is_ip })
}

/// The `rpId` a page may use: its own host, or a suffix of it that is itself
/// a registrable name — `login.example.com` may say `example.com`, nobody may
/// say `com`, `co.uk` or `github.io`. Absent means the host.
pub fn rp_id(origin: &Origin, asked: Option<&str>) -> anyhow::Result<String> {
    let Some(asked) = asked else { return Ok(origin.host.clone()) };
    let asked = asked.trim().trim_end_matches('.').to_ascii_lowercase();
    if asked.is_empty() || asked.len() > 253 || !asked.is_ascii() {
        return Err(keyward_core::fault!("err.passkeyWrongSite"));
    }
    if asked == origin.host {
        return Ok(asked);
    }
    let suffix_of_host = !origin.is_ip && origin.host.ends_with(&format!(".{asked}"));
    // `domain_str` is the registrable part of a name, `None` for a bare public
    // suffix; the name must be at least that.
    let registrable = psl::domain_str(&asked).is_some();
    if suffix_of_host && registrable {
        Ok(asked)
    } else {
        Err(keyward_core::fault!("err.passkeyWrongSite"))
    }
}

pub fn check_challenge(challenge: &[u8]) -> anyhow::Result<()> {
    if (CHALLENGE_MIN..=CHALLENGE_MAX).contains(&challenge.len()) {
        Ok(())
    } else {
        Err(keyward_core::fault!("err.passkeyBadRequest"))
    }
}

/// `user.id`: one to sixty-four bytes, says the spec.
pub fn check_user_id(user_id: &[u8]) -> anyhow::Result<()> {
    if (1..=64).contains(&user_id.len()) {
        Ok(())
    } else {
        Err(keyward_core::fault!("err.passkeyBadRequest"))
    }
}

/// Whether the client data is for a sign-in or a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    Get,
    Create,
}

/// `clientDataJSON`, in the order the spec's limited verification algorithm
/// expects: `type`, `challenge`, `origin`, `crossOrigin`. Only a top-level
/// page is served, so `crossOrigin` is always false.
pub fn client_data(ceremony: Ceremony, challenge: &[u8], origin: &Origin) -> Vec<u8> {
    let kind = match ceremony {
        Ceremony::Get => "webauthn.get",
        Ceremony::Create => "webauthn.create",
    };
    let quoted = |s: &str| serde_json::to_string(s).expect("a string always serialises");
    format!(
        r#"{{"type":{},"challenge":{},"origin":{},"crossOrigin":false}}"#,
        quoted(kind),
        quoted(&keyward_core::passkey::encode(challenge)),
        quoted(&origin.serialized),
    )
    .into_bytes()
}

pub fn hash(client_data: &[u8]) -> Vec<u8> {
    Sha256::digest(client_data).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_secure_origin_is_taken() {
        let o = origin("https://Login.Example.COM").unwrap();
        assert_eq!(o.serialized, "https://login.example.com");
        assert_eq!(o.host, "login.example.com");
        assert_eq!(origin("https://example.com:8443/path?q").unwrap().serialized, "https://example.com:8443");
        assert_eq!(origin("http://localhost:3000").unwrap().serialized, "http://localhost:3000");

        for bad in ["http://example.com", "ftp://example.com", "file:///etc/passwd", "javascript:alert(1)", "https://user:pw@example.com", "nonsense", ""] {
            assert!(origin(bad).is_err(), "{bad} is refused");
        }
    }

    #[test]
    fn a_page_may_claim_its_host_or_a_registrable_suffix() {
        let o = origin("https://login.example.com").unwrap();
        assert_eq!(rp_id(&o, None).unwrap(), "login.example.com");
        assert_eq!(rp_id(&o, Some("login.example.com")).unwrap(), "login.example.com");
        assert_eq!(rp_id(&o, Some("Example.com")).unwrap(), "example.com");
        for bad in ["com", "other.com", "xample.com", "evil-example.com", "sub.login.example.com", ""] {
            assert!(rp_id(&o, Some(bad)).is_err(), "{bad} is refused");
        }
    }

    #[test]
    fn a_public_suffix_is_never_an_rp_id() {
        let o = origin("https://shop.example.co.uk").unwrap();
        assert!(rp_id(&o, Some("co.uk")).is_err());
        assert_eq!(rp_id(&o, Some("example.co.uk")).unwrap(), "example.co.uk");
        // A private suffix too: one github.io page must not speak for all.
        let o = origin("https://me.github.io").unwrap();
        assert!(rp_id(&o, Some("github.io")).is_err());
    }

    #[test]
    fn an_address_claims_only_itself() {
        let o = origin("https://10.0.0.1").unwrap();
        assert!(o.is_ip);
        assert_eq!(rp_id(&o, Some("10.0.0.1")).unwrap(), "10.0.0.1");
        assert!(rp_id(&o, Some("0.0.1")).is_err());
    }

    #[test]
    fn the_client_data_is_in_the_specs_order() {
        let o = origin("https://example.com").unwrap();
        let data = client_data(Ceremony::Get, &[1, 2, 3], &o);
        assert_eq!(
            String::from_utf8(data).unwrap(),
            r#"{"type":"webauthn.get","challenge":"AQID","origin":"https://example.com","crossOrigin":false}"#
        );
        let data = client_data(Ceremony::Create, &[0xff], &o);
        assert!(String::from_utf8(data).unwrap().starts_with(r#"{"type":"webauthn.create","challenge":"_w""#));
    }

    #[test]
    fn challenges_and_user_ids_are_bounded() {
        assert!(check_challenge(&[0; 15]).is_err());
        assert!(check_challenge(&[0; 16]).is_ok());
        assert!(check_challenge(&vec![0; CHALLENGE_MAX + 1]).is_err());
        assert!(check_user_id(&[]).is_err());
        assert!(check_user_id(&[0; 64]).is_ok());
        assert!(check_user_id(&[0; 65]).is_err());
    }
}
