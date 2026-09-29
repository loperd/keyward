//! Choosing a server, as in the official client: ready-made regions or a host
//! of your own.

/// The official server in the US. The default, as in the Bitwarden client.
pub const US: &str = "https://vault.bitwarden.com";
/// The official server in Europe.
pub const EU: &str = "https://vault.bitwarden.eu";

/// Where to connect.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "region", rename_all = "snake_case")]
pub enum Region {
    Us,
    Eu,
    /// Self-hosted: Vaultwarden or an installation of Bitwarden of your own.
    SelfHosted { base_url: String },
}

impl Region {
    pub fn base_url(&self) -> &str {
        match self {
            Self::Us => US,
            Self::Eu => EU,
            Self::SelfHosted { base_url } => base_url,
        }
    }

    /// Works the region out from the stored address, so that the form opens
    /// in the state it was left in.
    pub fn from_base_url(url: &str) -> Self {
        match url.trim().trim_end_matches('/') {
            US => Self::Us,
            EU => Self::Eu,
            other => Self::SelfHosted { base_url: other.to_string() },
        }
    }
}

impl Default for Region {
    fn default() -> Self {
        Self::Us
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_urls_are_recognised_back() {
        assert_eq!(Region::from_base_url(US), Region::Us);
        assert_eq!(Region::from_base_url("https://vault.bitwarden.eu/"), Region::Eu);
    }

    #[test]
    fn anything_else_is_self_hosted() {
        let r = Region::from_base_url("https://vaultwarden.example.net/");
        assert_eq!(r, Region::SelfHosted { base_url: "https://vaultwarden.example.net".into() });
        assert_eq!(r.base_url(), "https://vaultwarden.example.net");
    }

    #[test]
    fn default_is_the_official_server() {
        assert_eq!(Region::default().base_url(), US);
    }
}
