//! Reaching a server: the connection, the host key, the key the vault holds.
//!
//! The client is russh — pure Rust on tokio, so the terminal is the same code
//! on macOS, Linux and Windows, with no system ssh and no local pty in the way.
//!
//! The private key never comes here. Authentication goes the way the agent's
//! does: the server asks for a signature, and the core makes it (`sign_ssh`),
//! asking for the person's finger. A health check does not even get that far:
//! russh offers the key first without a signature, a server that would take it
//! answers `PK_OK`, and the check stops right there — nothing is signed, nobody
//! is asked.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use keyward_plugin::Host;
use russh::client::{self, AuthResult, Handle};
use russh::keys::agent::AgentIdentity;
use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};

use super::hostkeys::{self, Source, Store, Verdict};

/// How long reaching a server may take before it counts as unreachable:
/// name resolution and the TCP connection together. A person waiting on a
/// shell gets longer than a background check.
pub const REACH: Duration = Duration::from_secs(10);

/// What the terminal asks a person about an unknown host.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HostPrompt {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub algorithm: String,
    /// Keys of other kinds are recorded for the host: the server offered a
    /// kind it was not known by.
    pub others: bool,
}

/// Asks a person whether to trust an unknown host and waits for the answer.
pub type AskTrust = Arc<dyn Fn(HostPrompt) -> tokio::sync::oneshot::Receiver<bool> + Send + Sync>;

/// What the handshake learned about the host key.
#[derive(Debug, Clone)]
pub struct Seen {
    pub key: PublicKey,
    pub verdict: Verdict,
}

/// The russh handler: it decides about the host key, and nothing else.
pub struct Guard {
    host: String,
    port: u16,
    pin: Option<String>,
    store: Store,
    seen: Arc<Mutex<Option<Seen>>>,
    /// `None` for a health check: an unknown host is reported, not asked
    /// about.
    ask: Option<AskTrust>,
}

impl Guard {
    pub fn new(host: &str, port: u16, pin: Option<String>, store: Store, ask: Option<AskTrust>) -> (Self, Arc<Mutex<Option<Seen>>>) {
        let seen = Arc::new(Mutex::new(None));
        (Self { host: host.to_string(), port, pin, store, seen: Arc::clone(&seen), ask }, seen)
    }
}

fn plain_key(presented: &PublicKeyOrCertificate) -> PublicKey {
    match presented {
        PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
        // A host certificate is judged by the key inside it: the terminal does
        // not keep certificate authorities.
        PublicKeyOrCertificate::Certificate(cert) => PublicKey::from(cert.public_key().clone()),
    }
}

impl client::Handler for Guard {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, presented: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let key = plain_key(presented);
        let verdict = self.store.verify(&self.host, self.port, &key, self.pin.as_deref())?;
        let record = |verdict: Verdict| {
            if let Ok(mut slot) = self.seen.lock() {
                *slot = Some(Seen { key: key.clone(), verdict });
            }
        };
        record(verdict.clone());
        match verdict {
            Verdict::Pinned | Verdict::Known(_) => Ok(true),
            Verdict::Changed(source) => {
                tracing::warn!(host = %self.host, port = self.port, ?source, "the host key does not match the recorded one; refused");
                Ok(false)
            }
            Verdict::Unknown { others } => {
                let Some(ask) = &self.ask else { return Ok(false) };
                let answer = ask(HostPrompt {
                    host: self.host.clone(),
                    port: self.port,
                    fingerprint: hostkeys::fingerprint(&key),
                    algorithm: key.algorithm().to_string(),
                    others,
                });
                // A person who never answers is a no, and the server gives up
                // on a silent client after two minutes anyway.
                let yes = matches!(tokio::time::timeout(Duration::from_secs(120), answer).await, Ok(Ok(true)));
                if !yes {
                    return Ok(false);
                }
                self.store.learn(&self.host, self.port, &key)?;
                record(Verdict::Known(Source::Keyward));
                Ok(true)
            }
        }
    }
}

/// Why a connection did not come up, in the words a person reads.
pub fn reach_error(host: &str, e: impl std::fmt::Display) -> anyhow::Error {
    keyward_core::fault!("err.sshUnreachable", "host" => host, "reason" => e.to_string())
}

/// The client's settings: keepalives so a dead link is noticed, nothing more.
fn config() -> Arc<client::Config> {
    Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        ..Default::default()
    })
}

/// Connects and runs the key exchange. `Err` with `Seen` means the host key
/// was the reason; without it the host was not reached at all.
pub async fn handshake(
    host: &str,
    port: u16,
    reach: Duration,
    guard: Guard,
    seen: &Arc<Mutex<Option<Seen>>>,
) -> Result<Handle<Guard>, (anyhow::Error, Option<Seen>)> {
    let last_seen = || seen.lock().ok().and_then(|s| s.clone());
    let stream = match tokio::time::timeout(reach, tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err((reach_error(host, e), None)),
        Err(_) => return Err((reach_error(host, "timed out"), None)),
    };
    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!(error = %e, "TCP_NODELAY was not set; keystrokes may lag");
    }
    match client::connect_stream(config(), stream, guard).await {
        Ok(handle) => Ok(handle),
        Err(e) => {
            let seen = last_seen();
            let err = match &seen {
                Some(s) => host_key_error(host, port, s).unwrap_or_else(|| reach_error(host, &e)),
                None => reach_error(host, &e),
            };
            Err((err, seen))
        }
    }
}

/// The refusal a person reads when the host key was the reason.
pub fn host_key_error(host: &str, port: u16, seen: &Seen) -> Option<anyhow::Error> {
    let fingerprint = hostkeys::fingerprint(&seen.key);
    match &seen.verdict {
        Verdict::Changed(Source::Pin) => Some(keyward_core::fault!("err.sshHostKeyNotPinned", "host" => host, "fingerprint" => fingerprint)),
        Verdict::Changed(_) => Some(keyward_core::fault!("err.sshHostKeyChanged", "host" => host, "port" => port, "fingerprint" => fingerprint)),
        Verdict::Unknown { .. } => Some(keyward_core::fault!("err.sshHostKeyDeclined", "host" => host, "fingerprint" => fingerprint)),
        Verdict::Pinned | Verdict::Known(_) => None,
    }
}

/// The RSA hash to sign with, as the server advertises it. Other kinds have
/// one.
async fn hash_for(handle: &Handle<Guard>, key: &PublicKey) -> Option<HashAlg> {
    if !matches!(key.algorithm(), Algorithm::Rsa { .. }) {
        return None;
    }
    match handle.best_supported_rsa_hash().await {
        Ok(Some(hash)) => hash,
        // The server did not say: SHA-256, as OpenSSH assumes of a modern one.
        Ok(None) => Some(HashAlg::Sha256),
        Err(e) => {
            tracing::warn!(error = %e, "the server's signature algorithms are unknown; SHA-256 is assumed");
            Some(HashAlg::Sha256)
        }
    }
}

// -- Signing through the core -----------------------------------------------

/// A signer's failure: the core refused, or the session went away.
#[derive(Debug)]
pub struct SignFailed(pub anyhow::Error);

impl From<russh::SendError> for SignFailed {
    fn from(_: russh::SendError) -> Self {
        Self(anyhow::anyhow!("the ssh session went away while signing"))
    }
}

/// Signs through the core. The core holds the key, and it asks the person.
pub struct CoreSigner {
    pub core: Arc<dyn Host>,
    pub entry_id: String,
    pub confirm: bool,
}

/// The agent protocol's flags for an RSA hash: what `sign_ssh` takes.
fn agent_flags(hash: Option<HashAlg>) -> u32 {
    match hash {
        Some(HashAlg::Sha256) => 2,
        Some(HashAlg::Sha512) => 4,
        _ => 0,
    }
}

/// The signature's algorithm name out of the core's wire form, checked
/// against what was asked: a SHA-1 signature where SHA-2 was asked for is a
/// downgrade, not a detail.
fn check_wire(wire: &[u8], key: &PublicKey, hash: Option<HashAlg>) -> anyhow::Result<()> {
    use ssh_encoding::Decode as _;
    let mut reader = wire;
    let name = String::decode(&mut reader).map_err(|e| anyhow::anyhow!("the core's signature will not parse: {e}"))?;
    let want = match key.algorithm() {
        Algorithm::Rsa { .. } => match hash {
            Some(HashAlg::Sha256) => "rsa-sha2-256".to_string(),
            Some(HashAlg::Sha512) => "rsa-sha2-512".to_string(),
            _ => "ssh-rsa".to_string(),
        },
        other => other.as_str().to_string(),
    };
    if name != want {
        anyhow::bail!("the core signed with {name}, while {want} was asked for");
    }
    Ok(())
}

impl russh::Signer for CoreSigner {
    type Error = SignFailed;

    fn auth_sign(
        &mut self,
        identity: &AgentIdentity,
        hash: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send {
        let key = match identity {
            AgentIdentity::PublicKey { key, .. } => Ok(key.clone()),
            AgentIdentity::Certificate { .. } => Err(SignFailed(anyhow::anyhow!("the terminal does not sign with certificates"))),
        };
        let core = Arc::clone(&self.core);
        let entry_id = self.entry_id.clone();
        let confirm = self.confirm;
        async move {
            let key = key?;
            let wire = core.sign_ssh(&entry_id, &to_sign, agent_flags(hash), confirm).await.map_err(SignFailed)?;
            check_wire(&wire, &key, hash).map_err(SignFailed)?;
            let len = u32::try_from(wire.len()).map_err(|_| SignFailed(anyhow::anyhow!("the core's signature is too long")))?;
            to_sign.extend_from_slice(&len.to_be_bytes());
            to_sign.extend_from_slice(&wire);
            Ok(to_sign)
        }
    }
}

/// Logs in with the vault's key. `Ok(false)` means the server would not have
/// it.
pub async fn login(handle: &mut Handle<Guard>, user: &str, key: &PublicKey, signer: &mut CoreSigner) -> anyhow::Result<bool> {
    let hash = hash_for(handle, key).await;
    match handle.authenticate_publickey_with(user, key.clone(), hash, signer).await {
        Ok(AuthResult::Success) => Ok(true),
        Ok(AuthResult::Failure { .. }) => Ok(false),
        Err(SignFailed(e)) => Err(e),
    }
}

// -- The probe ----------------------------------------------------------------

/// The signer of a health check: it is asked only after the server answered
/// `PK_OK`, and it refuses — that answer is all the check wanted.
struct Probe;

/// The probe's own refusal, told apart from a real failure.
const ACCEPTED: &str = "\u{1}accepted";

impl russh::Signer for Probe {
    type Error = SignFailed;

    async fn auth_sign(&mut self, _identity: &AgentIdentity, _hash: Option<HashAlg>, _to_sign: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        Err(SignFailed(anyhow::anyhow!(ACCEPTED)))
    }
}

/// Would the server take this key for this login? Nothing is signed.
pub async fn probe(handle: &mut Handle<Guard>, user: &str, key: &PublicKey) -> anyhow::Result<bool> {
    let hash = hash_for(handle, key).await;
    match handle.authenticate_publickey_with(user, key.clone(), hash, &mut Probe).await {
        Err(SignFailed(e)) if e.to_string() == ACCEPTED => Ok(true),
        Ok(AuthResult::Failure { .. }) => Ok(false),
        // A server that lets a key in without a signature is broken, not
        // healthy.
        Ok(AuthResult::Success) => anyhow::bail!("the server let the key in without a signature"),
        Err(SignFailed(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_flags_follow_the_agent_protocol() {
        assert_eq!(agent_flags(None), 0);
        assert_eq!(agent_flags(Some(HashAlg::Sha256)), 2);
        assert_eq!(agent_flags(Some(HashAlg::Sha512)), 4);
    }

    #[test]
    fn a_downgraded_signature_is_refused() {
        use ssh_encoding::Encode as _;
        let ed = russh::keys::parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ").unwrap();
        let mut wire = Vec::new();
        "ssh-ed25519".encode(&mut wire).unwrap();
        [0u8; 64].as_slice().encode(&mut wire).unwrap();
        assert!(check_wire(&wire, &ed, None).is_ok());

        let mut other = Vec::new();
        "ssh-rsa".encode(&mut other).unwrap();
        assert!(check_wire(&other, &ed, None).is_err());
    }
}
