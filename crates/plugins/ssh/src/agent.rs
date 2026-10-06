//! The ssh agent: one socket, one mapping, **exactly one** identity.
//!
//! This is what keyward is for. A classic agent hands ssh every key, ssh tries
//! them one after another and runs into `MaxAuthTries`. Here ssh physically
//! sees nothing but the key it needs — not by agreement, but because there is
//! nothing else on that socket.

use std::sync::Arc;

use anyhow::Context as _;
use crate::mapping::Mapping;
use keyward_ssh_client::hostkeys::same_key;
use keyward_core::source::VaultEntry;
use keyward_plugin::Host;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::extension::SessionBind;
use ssh_agent_lib::proto::{Extension, Identity, SignRequest};
use ssh_agent_lib::ssh_key::{PublicKey, Signature};
use tokio::net::UnixListener;

#[derive(Clone)]
pub struct HostAgent {
    entry: VaultEntry,
    mapping: Mapping,
    /// The core: it is what signs. A plugin has no private key — not an
    /// external one, not any: `entries` cuts it out.
    core: Arc<dyn Host>,
    /// Ask for confirmation on every signature: out of the settings or out of
    /// the `kw-confirm` mark on the item itself.
    confirm: bool,
    /// Signing is forbidden on this connection: the host key is not the one
    /// pinned in the item. The decision is taken once, when the session is
    /// bound, and holds to the end of the connection.
    refuse: bool,
}

impl HostAgent {
    fn public_key(&self) -> Result<PublicKey, AgentError> {
        let raw = self
            .entry
            .public_key
            .as_deref()
            .ok_or_else(|| AgentError::Other(anyhow::anyhow!(
                "the item {} has no public key", self.entry.name
            ).into()))?;
        raw.parse::<PublicKey>()
            .map_err(|e| AgentError::Other(anyhow::anyhow!("the public key of {} will not parse: {e}", self.entry.name).into()))
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for HostAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let pk = self.public_key()?;
        // Exactly one. If a second element ever appears here, back comes the
        // trying of key after key that the whole project was written to end.
        Ok(vec![Identity {
            pubkey: pk.key_data().clone(),
            comment: self.mapping.entry_name.clone(),
        }])
    }

    /// Binding the connection to an ssh session.
    ///
    /// `session-bind@openssh.com` is the only way for an agent to learn which
    /// host ssh is really talking to: the agent does not see the handshake
    /// itself. ssh sends the host key, the session identifier and a signature
    /// of that identifier by the host key — that is, proof that the host really
    /// owns the key.
    ///
    /// This is where the `kw-hostkey` mark gets its meaning: until now it was
    /// read, shown in the interface as a "host key pinned" tag, and meant
    /// nothing. Now a mismatch forbids signing on this connection: ssh gets a
    /// refusal rather than a key.
    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        let Some(bind) = extension.parse_message::<SessionBind>().ok().flatten() else {
            // An unfamiliar extension is none of our business.
            return Ok(None);
        };

        // The host's signature is always checked: without it the host key in
        // the message is merely somebody's assertion.
        if let Err(e) = bind.verify_signature() {
            self.refuse = true;
            tracing::warn!(host = %self.mapping.pattern, error = %e, "the host did not prove its key; signing is forbidden");
            return Err(AgentError::Other(
                anyhow::anyhow!("the host did not prove its key").into(),
            ));
        }

        let seen = bind.host_key.fingerprint(Default::default()).to_string();
        match self.mapping.hostkey.as_deref() {
            Some(pinned) if !same_key(pinned, &seen) => {
                self.refuse = true;
                tracing::warn!(
                    host = %self.mapping.pattern,
                    entry = %self.mapping.entry_name,
                    pinned = %pinned,
                    seen = %seen,
                    "the host key does not match the pinned one; signing is forbidden"
                );
                return Err(AgentError::Other(
                    anyhow::anyhow!("the host key does not match the one pinned in the item").into(),
                ));
            }
            Some(_) => {
                tracing::info!(host = %self.mapping.pattern, "the host key matched the pinned one");
            }
            None => {
                // There is nothing for us to pin with: a person edits the
                // item. The fingerprint goes into the log so that it can be
                // copied into the kw-hostkey field.
                tracing::info!(
                    host = %self.mapping.pattern,
                    fingerprint = %seen,
                    "the host key is not pinned; to pin it, put this fingerprint into kw-hostkey"
                );
            }
        }
        Ok(None)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        if self.refuse {
            return Err(AgentError::Other(
                anyhow::anyhow!("signing is forbidden: the host key is not the right one").into(),
            ));
        }
        let expected = self.public_key()?;
        if request.pubkey != *expected.key_data() {
            // One key lives on this socket; a request to sign with another is
            // either a mistake or an attempt to feel around for something.
            return Err(AgentError::Other(
                anyhow::anyhow!("a signature was asked for with a key that is not on this socket").into(),
            ));
        }

        // The core signs. It also asks for the confirmation: the sensor is its
        // business, and it sees the `kw-confirm` mark on the item itself. Only
        // the request travels from here: this mapping asks to be asked every
        // time.
        let wire = self
            .core
            .sign_ssh(&self.entry.id, &request.data, request.flags, self.confirm)
            .await
            .map_err(|e| AgentError::Other(e.into()))?;
        decode_signature(&wire)
    }
}

/// The core's signature in the shape ssh expects. The wire form is the same on
/// both sides: the algorithm's name and the bytes.
fn decode_signature(wire: &[u8]) -> Result<Signature, AgentError> {
    use ssh_encoding::Decode as _;
    let mut reader = wire;
    Signature::decode(&mut reader)
        .map_err(|e| AgentError::Other(anyhow::anyhow!("the core's signature will not parse: {e}").into()))
}

/// Brings up an agent socket for one particular mapping and returns the task
/// that serves it.
pub fn spawn(
    path: &std::path::Path,
    entry: VaultEntry,
    mapping: Mapping,
    confirm: bool,
    core: Arc<dyn Host>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    // A stale file from a previous run will not let us bind; it is removed.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("cannot take the agent socket {}", path.display()))?;

    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    let agent = HostAgent { entry, mapping, confirm, refuse: false, core };
    let sock_path = path.to_path_buf();
    tracing::info!(socket = %sock_path.display(), entry = %agent.mapping.entry_name, "the agent socket is up");

    Ok(tokio::spawn(async move {
        if let Err(e) = ssh_agent_lib::agent::listen(listener, agent).await {
            tracing::warn!(socket = %sock_path.display(), error = %e, "the agent stopped");
        }
    }))
}

/// The shared socket: every key of the vault on one socket.
///
/// This is exactly the classic agent keyward walks away from: ssh tries key
/// after key and runs into `MaxAuthTries`. But IDEs and git clients do not read
/// ssh_config and know only SSH_AUTH_SOCK, and this socket exists for them. It
/// is switched on deliberately, by a setting, and is off by default.
#[derive(Clone)]
pub struct VaultAgent {
    /// The list lives with the daemon and changes on every rebuild of the
    /// routes; the agent only reads.
    entries: std::sync::Arc<std::sync::RwLock<Vec<VaultEntry>>>,
    /// Confirm every signature: out of the settings.
    confirm_all: bool,
    /// The core: it is what signs.
    core: Arc<dyn Host>,
}

impl VaultAgent {
    fn snapshot(&self) -> Vec<VaultEntry> {
        self.entries.read().map(|e| e.clone()).unwrap_or_default()
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for VaultAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let mut out = Vec::new();
        for e in self.snapshot() {
            let Some(raw) = e.public_key.as_deref() else { continue };
            let Ok(pk) = raw.parse::<PublicKey>() else { continue };
            out.push(Identity { pubkey: pk.key_data().clone(), comment: e.name.clone() });
        }
        Ok(out)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let fail = |m: String| AgentError::Other(anyhow::anyhow!("{m}").into());
        let entry = self
            .snapshot()
            .into_iter()
            .find(|e| {
                e.public_key
                    .as_deref()
                    .and_then(|raw| raw.parse::<PublicKey>().ok())
                    .is_some_and(|pk| *pk.key_data() == request.pubkey)
            })
            .ok_or_else(|| fail("a signature was asked for with a key that is not in the vault".into()))?;

        let confirm = self.confirm_all || crate::table::is_yes(entry.field(crate::table::CONFIRM));
        let wire = self
            .core
            .sign_ssh(&entry.id, &request.data, request.flags, confirm)
            .await
            .map_err(|e| fail(e.to_string()))?;
        decode_signature(&wire)
    }
}

/// Brings up the shared socket with every key.
pub fn spawn_shared(
    path: &std::path::Path,
    entries: std::sync::Arc<std::sync::RwLock<Vec<VaultEntry>>>,
    confirm_all: bool,
    core: Arc<dyn Host>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("cannot take the shared agent socket {}", path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    let agent = VaultAgent { entries, confirm_all, core };
    let sock_path = path.to_path_buf();
    tracing::info!(socket = %sock_path.display(), "the shared agent socket is up");
    Ok(tokio::spawn(async move {
        if let Err(e) = ssh_agent_lib::agent::listen(listener, agent).await {
            tracing::warn!(socket = %sock_path.display(), error = %e, "the shared agent stopped");
        }
    }))
}
