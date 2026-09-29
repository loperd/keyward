//! Issuing access to HashiCorp Vault.
//!
//! The ledger keeps **accessors only** — a token is revoked by one, but it
//! cannot be used. The token itself is saved nowhere: it goes to whoever asked
//! and lives for minutes. So a leak of the ledger file gives access to not one
//! secret.

use serde::{Deserialize, Serialize};

/// What Vault knows about a token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenInfo {
    pub accessor: String,
    pub policies: Vec<String>,
    pub ttl_seconds: u64,
    /// -1 means no limit on the number of uses.
    pub num_uses: i64,
    pub display_name: String,
}

/// A root token lying in a hidden vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootToken {
    /// The Bitwarden item it lies in.
    pub entry_id: String,
    pub addr: String,
    /// When it was issued, in unix time. Zero means the item has no mark.
    pub issued_at: u64,
    /// What Vault itself said about it. `None` means the server did not
    /// recognise it: the token has been revoked or has expired, and there is no
    /// point keeping the item.
    pub info: Option<TokenInfo>,
}

/// A Vault ACL policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    /// The policy's body in HCL. The built-in `root` has none.
    pub rules: String,
}

/// A mounted secrets engine. A policy is built out of its path: writing the
/// path by hand is a sure way to grant rights to something that is not
/// there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    pub path: String,
    pub kind: String,
    pub description: String,
    /// kv of the second version: the data lies under `data/`, and a policy
    /// without that prefix grants nothing.
    pub kv2: bool,
    #[serde(default)]
    pub accessor: String,
    /// Seconds; 0 means the system's value.
    #[serde(default)]
    pub default_lease_ttl: u64,
    #[serde(default)]
    pub max_lease_ttl: u64,
    /// An auth method (`auth/...`) rather than a secrets engine.
    #[serde(default)]
    pub auth: bool,
}

/// What is filled in when mounting an engine or an auth method.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MountForm {
    pub path: String,
    pub kind: String,
    #[serde(default)]
    pub description: String,
    /// For kv: 1 or 2. The others do not need it.
    #[serde(default)]
    pub kv_version: Option<u8>,
    /// Strings of the form `768h`; empty means the system's value.
    #[serde(default)]
    pub default_lease_ttl: String,
    #[serde(default)]
    pub max_lease_ttl: String,
    /// Mount as an auth method rather than a secrets engine.
    #[serde(default)]
    pub auth: bool,
}

impl MountForm {
    pub fn validate(&self) -> Result<(), String> {
        let path = self.path.trim().trim_matches('/');
        if path.is_empty() {
            return Err("err.enginePathRequired".into());
        }
        if path.split('/').any(|s| s.is_empty() || s == "..") || !path.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.')) {
            return Err("err.enginePathCharset".into());
        }
        if ["sys", "auth", "identity", "cubbyhole"].contains(&path) {
            return Err(key("err.enginePathReserved", &[("path", path)]));
        }
        if self.kind.trim().is_empty() {
            return Err("err.engineKindRequired".into());
        }
        for (name, v) in [("default_lease_ttl", &self.default_lease_ttl), ("max_lease_ttl", &self.max_lease_ttl)] {
            if !v.trim().is_empty() && !is_duration(v.trim()) {
                return Err(key("err.durationFormat", &[("field", name)]));
            }
        }
        if let Some(v) = self.kv_version {
            if !matches!(v, 1 | 2) {
                return Err("err.kvVersion".into());
            }
        }
        Ok(())
    }
}

/// A named refusal in the wire form the window understands: the key and the
/// values that fill it. The plugin does not know which language the window
/// speaks, so it never writes the sentence itself.
pub fn key(code: &str, args: &[(&str, &str)]) -> String {
    let mut fault = keyward_core::fault::Fault::new(code);
    for (name, value) in args {
        fault = fault.with(*name, value);
    }
    fault.to_string()
}

/// A Vault duration string: a number and a unit of s, m or h.
pub fn is_duration(s: &str) -> bool {
    let s = s.trim();
    s.len() >= 2 && s[..s.len() - 1].chars().all(|c| c.is_ascii_digit()) && matches!(s.chars().last(), Some('s' | 'm' | 'h'))
}

/// Editing a mounted engine's settings. `None` means leave it alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MountTune {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default_lease_ttl: Option<String>,
    #[serde(default)]
    pub max_lease_ttl: Option<String>,
    /// For kv only: moving to version 2. There is no way back.
    #[serde(default)]
    pub kv_version: Option<u8>,
}

/// A kv v2 engine's settings in full: they hold for every secret that has
/// none of its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KvConfig {
    pub max_versions: u64,
    pub cas_required: bool,
    pub delete_version_after: String,
}

/// The state of a Vault server: what is visible without special rights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub initialized: bool,
    pub sealed: bool,
    pub standby: bool,
    pub version: Option<String>,
}

/// The seal's state. Shamir needs a threshold of `t` out of `n` keys, and
/// `progress` shows how many have been entered: without it, unsealing is
/// guesswork.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealStatus {
    #[serde(rename = "type", default)]
    pub kind: String,
    pub initialized: bool,
    pub sealed: bool,
    #[serde(default)]
    pub t: u32,
    #[serde(default)]
    pub n: u32,
    #[serde(default)]
    pub progress: u32,
    #[serde(default)]
    pub version: Option<String>,
}

impl SealStatus {
    /// How many keys still have to be entered.
    pub fn keys_needed(&self) -> u32 {
        if !self.sealed {
            return 0;
        }
        self.t.saturating_sub(self.progress)
    }
}

/// The progress of generating a root token.
///
/// Vault does not give a root token on one request: an attempt is started with
/// a one-time key, the shares are fed into it one after another, and only at
/// the threshold does the token come back — encrypted with that one-time
/// key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootProgress {
    pub nonce: String,
    /// How many shares are needed altogether and how many have been taken.
    pub required: u32,
    pub progress: u32,
    pub complete: bool,
    /// The finished token: it arrives only at the last step and only once.
    pub token: Option<String>,
}

/// Whom it is issued to. The distinction matters for a reason: an agent needs
/// a one-off token for minutes, a person one for the length of a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recipient {
    Agent,
    Person,
    Me,
}

impl Recipient {
    /// Sensible defaults for the recipient.
    pub fn defaults(self) -> (u32, u32) {
        match self {
            // An agent gets a quarter of an hour with no limit on calls.
            //
            // A single use sounded elegant and did not work: every Vault
            // client, its own CLI included, starts by asking
            // `auth/token/lookup-self`, and the one use burnt up on that check.
            // After that the agent got a 403 "invalid token" for everything and
            // rightly reckoned the token dead. The protection here is a short
            // life, not a counter.
            Self::Agent => (900, 0),
            Self::Person => (3600, 0),
            Self::Me => (1800, 0),
        }
    }
}

/// What is asked of Vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRequest {
    pub recipient: Recipient,
    /// Vault's policies. An empty list means inheriting the broker's policies,
    /// which is almost never what anybody wanted.
    pub policies: Vec<String>,
    /// The lifetime in seconds.
    pub ttl_seconds: u32,
    /// How many times the token may be used; 0 means no limit.
    pub num_uses: u32,
    /// Hand it over in a one-time wrapper instead of the token itself.
    pub wrap: bool,
    /// A note: to whom and what for.
    #[serde(default)]
    pub note: String,
    /// Consent to full rights: `root` or any policy with `sudo`.
    ///
    /// A flag of its own rather than a silent permission: such a token equals
    /// the very root we hide in a hidden item, and missing it in a list of
    /// policies is far too easy.
    #[serde(default)]
    pub wide_ok: bool,
}

/// The policy keyward creates itself: the right to create and edit Vault's
/// policies. It exists so that an agent can be given a short token to
/// bootstrap with — to describe its own paths without begging for root.
pub const POLICY_ADMIN: &str = "keyward-policy-admin";

/// The body of `POLICY_ADMIN`. It is written to Vault whole every time: if
/// somebody edited it by hand, the next issue returns it to its canonical
/// form.
///
/// It does not allow policies to be assigned to tokens: Vault has separate
/// paths for that and they are not included here. Nor is deletion: a bootstrap
/// does not need it.
pub const POLICY_ADMIN_RULES: &str = r#"# Issued by keyward: to create and edit Vault policies.
path "sys/policies/acl/*" {
  capabilities = ["create", "update", "read", "list"]
}

path "sys/policies/acl" {
  capabilities = ["list"]
}

# So that the engines and the names of their paths can be seen.
path "sys/mounts" {
  capabilities = ["read"]
}

path "sys/internal/ui/mounts" {
  capabilities = ["read"]
}

path "sys/internal/ui/mounts/*" {
  capabilities = ["read"]
}
"#;

/// Does the policy grant full rights?
///
/// The right to write policies is included: whoever can rewrite any policy can
/// widen the rights of any token bound to it.
pub fn is_wide(policy: &str) -> bool {
    let p = policy.trim().to_ascii_lowercase();
    p == "root" || p.starts_with("sudo") || p == POLICY_ADMIN
}

impl IssueRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.policies.is_empty() {
            return Err("err.policyRequired".into());
        }
        if self.policies.iter().any(|p| p.trim().is_empty()) {
            return Err("err.policyNameEmpty".into());
        }
        // The point of a broker is narrow temporary access, so full rights need
        // a "yes" of their own. Forbidding them altogether turned out to be
        // wrong: a Vault administrator needs them — to create an auth method,
        // for instance — and the ban simply drove people out into an unrecorded
        // root.
        if let Some(wide) = self.policies.iter().find(|p| is_wide(p)) {
            if !self.wide_ok {
                return Err(key("err.policyIsRoot", &[("policy", wide)]));
            }
            // The life here is shorter than a day: full rights for a day are
            // not temporary access but a second copy of root.
            if self.ttl_seconds > 3_600 {
                return Err("err.rootRightsHour".into());
            }
        }
        if self.ttl_seconds == 0 {
            return Err("err.ttlRequired".into());
        }
        if self.ttl_seconds > 86_400 {
            return Err("err.ttlOverADay".into());
        }
        Ok(())
    }
}

/// A secret out of a kv engine: the values as strings, the way they are
/// kept.
///
/// Numbers and booleans out of kv v1 are turned into strings: the interface
/// shows text anyway, and on a write Vault takes strings without question.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secret {
    pub mount: String,
    pub path: String,
    pub data: std::collections::BTreeMap<String, String>,
    /// The version in kv v2; kv v1 has no versions.
    pub version: Option<u64>,
    /// When it was written (kv v2, RFC 3339).
    pub updated: Option<String>,
}

/// By hand: the values are secrets, and `Debug` is what reaches a log.
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({}:{}, {} keys, v{:?})", self.mount, self.path, self.data.len(), self.version)
    }
}

impl Secret {
    /// What the window is shown: the keys and how long each value is. A value
    /// is fetched one at a time, on "show", or copied by the plugin itself.
    pub fn view(&self) -> SecretView {
        SecretView {
            mount: self.mount.clone(),
            path: self.path.clone(),
            fields: self.data.iter().map(|(k, v)| FieldView { key: k.clone(), length: v.chars().count() }).collect(),
            version: self.version,
            updated: self.updated.clone(),
        }
    }
}

/// A secret as the window sees it: no values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretView {
    pub mount: String,
    pub path: String,
    pub fields: Vec<FieldView>,
    pub version: Option<u64>,
    pub updated: Option<String>,
}

/// One key of a secret and the length of its value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldView {
    pub key: String,
    pub length: usize,
}

/// One version of a kv v2 secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretVersion {
    pub version: u64,
    pub created: Option<String>,
    /// Soft-deleted: the data is hidden but can be brought back.
    pub deleted: Option<String>,
    /// Destroyed: the data is gone.
    pub destroyed: bool,
}

/// A kv v2 secret's metadata: versions, limits, custom fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    pub mount: String,
    pub path: String,
    pub current_version: u64,
    pub oldest_version: u64,
    pub max_versions: u64,
    pub cas_required: bool,
    pub delete_version_after: String,
    pub custom_metadata: std::collections::BTreeMap<String, String>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub versions: Vec<SecretVersion>,
}

/// What to change in the metadata. `None` means leave it alone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMetaPatch {
    #[serde(default)]
    pub max_versions: Option<u64>,
    #[serde(default)]
    pub cas_required: Option<bool>,
    #[serde(default)]
    pub delete_version_after: Option<String>,
    #[serde(default)]
    pub custom_metadata: Option<std::collections::BTreeMap<String, String>>,
}

/// An issue's state in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum IssueState {
    Active,
    Revoked,
    /// Vault reported that there is no such accessor any more: the token
    /// expired on its own.
    Expired,
}

/// A record in the ledger. There is no token here and there cannot be.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issued {
    pub accessor: String,
    pub recipient: Recipient,
    pub policies: Vec<String>,
    pub ttl_seconds: u32,
    pub num_uses: u32,
    pub note: String,
    /// Seconds since the epoch: how much is left is counted from this.
    pub created_at: u64,
    pub wrapped: bool,
    pub state: IssueState,
}

impl Issued {
    /// How many seconds are left by our reckoning. Vault knows the real
    /// deadline, but something has to be shown without asking it.
    pub fn remaining(&self, now: u64) -> i64 {
        let ends = self.created_at as i64 + i64::from(self.ttl_seconds);
        ends - now as i64
    }

    pub fn looks_expired(&self, now: u64) -> bool {
        self.state == IssueState::Active && self.remaining(now) <= 0
    }
}

/// The result of an issue, for the interface: either a wrapper or the token
/// itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueResult {
    pub issued: Issued,
    /// The one-time wrapper. When it is there, the token itself will not be.
    pub wrapping_token: Option<String>,
    /// The token, only when no wrapper was asked for.
    pub token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> IssueRequest {
        IssueRequest {
            recipient: Recipient::Agent,
            policies: vec!["ro-dev".into()],
            ttl_seconds: 300,
            num_uses: 1,
            wrap: true,
            note: String::new(),
            wide_ok: false,
        }
    }

    #[test]
    fn seal_status_counts_remaining_keys() {
        let mut st = SealStatus {
            kind: "shamir".into(), initialized: true, sealed: true,
            t: 3, n: 5, progress: 1, version: None,
        };
        assert_eq!(st.keys_needed(), 2);
        st.sealed = false;
        // An unsealed Vault needs no keys, whatever the progress says.
        assert_eq!(st.keys_needed(), 0);
    }

    #[test]
    fn policies_are_required() {
        let mut r = req();
        r.policies.clear();
        // A token with no policies inherits the broker's rights, which is
        // exactly what issuing temporary access must not allow.
        assert!(r.validate().is_err());
    }

    #[test]
    fn lifetime_is_bounded() {
        let mut r = req();
        r.ttl_seconds = 0;
        assert!(r.validate().is_err());
        r.ttl_seconds = 86_401;
        assert!(r.validate().is_err());
        r.ttl_seconds = 900;
        assert!(r.validate().is_ok());
    }

    #[test]
    fn full_privileges_need_a_separate_yes() {
        let mut r = req();
        r.policies = vec!["sudo-ops".into()];
        assert!(r.validate().is_err(), "full rights must not be issued silently");

        r.wide_ok = true;
        assert!(r.validate().is_ok());

        // An hour is the limit: full rights for a day are not temporary
        // access.
        r.ttl_seconds = 7_200;
        assert!(r.validate().is_err());

        // An ordinary policy needs no consent and may still have a day.
        let mut ordinary = req();
        ordinary.ttl_seconds = 7_200;
        assert!(ordinary.validate().is_ok());
    }

    #[test]
    fn policy_admin_counts_as_wide() {
        let r = IssueRequest { policies: vec![POLICY_ADMIN.into()], ..req() };
        assert!(r.validate().is_err(), "the right to write policies is full rights and needs a yes of its own");
        let ok = IssueRequest { wide_ok: true, ttl_seconds: 900, ..r.clone() };
        assert!(ok.validate().is_ok());
        let long = IssueRequest { wide_ok: true, ttl_seconds: 7_200, ..r };
        assert!(long.validate().is_err(), "and no longer than an hour");
        assert!(POLICY_ADMIN_RULES.contains("sys/policies/acl/*"));
        assert!(!POLICY_ADMIN_RULES.contains("auth/token"), "it must not assign policies to tokens");
    }

    #[test]
    fn agent_gets_a_short_life_and_not_a_single_use() {
        let (ttl, uses) = Recipient::Agent.defaults();
        assert_eq!(ttl, 900, "a quarter of an hour is enough for an agent");
        assert_eq!(
            uses, 0,
            "a single use burns up on the client's own check: every Vault client \
             starts with auth/token/lookup-self, and the token is dead before the useful request"
        );
        let (_, uses) = Recipient::Person.defaults();
        assert_eq!(uses, 0, "a one-use token gets in a person's way");
    }

    #[test]
    fn remaining_time_counts_down_and_goes_negative() {
        let issued = Issued {
            accessor: "a".into(),
            recipient: Recipient::Me,
            policies: vec!["p".into()],
            ttl_seconds: 100,
            num_uses: 0,
            note: String::new(),
            created_at: 1_000,
            wrapped: false,
            state: IssueState::Active,
        };
        assert_eq!(issued.remaining(1_040), 60);
        assert!(!issued.looks_expired(1_040));
        assert!(issued.looks_expired(1_200));
    }
}
