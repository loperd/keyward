//! An ssh key item's own material: making a new pair, reading one a person
//! pastes in, and deriving what the item shows — the public key and the
//! fingerprint — from the private key rather than taking them on trust.
//!
//! The private key is stored the way Bitwarden's own clients store it and the
//! way the ssh agent reads it: OpenSSH format, unencrypted (the vault is the
//! encryption). A key pasted in another format, or under a passphrase, is
//! normalised into that on the way in.

use keyward_core::edits::SshAlgorithm;
use ssh_key::{HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

/// What an ssh key item holds, in the clear. Deliberately not `Debug`: it
/// must never reach a log.
pub struct Material {
    pub private_key: Zeroizing<String>,
    pub public_key: String,
    pub fingerprint: String,
}

/// What can be shown about a key without its secret half.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Summary {
    pub public_key: String,
    pub fingerprint: String,
    /// `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256` and so on.
    pub algorithm: String,
}

impl Material {
    pub fn summary(&self) -> Summary {
        let algorithm = self.public_key.split_whitespace().next().unwrap_or_default().to_string();
        Summary { public_key: self.public_key.clone(), fingerprint: self.fingerprint.clone(), algorithm }
    }
}

/// RSA keys are made this size: 2048 is still accepted everywhere but is on
/// its way out, and generating is a one-off.
const RSA_BITS: usize = 4096;

/// Make a new key pair. The comment goes into the public key line, the way
/// `ssh-keygen -C` puts it.
pub fn generate(algorithm: SshAlgorithm, comment: &str) -> anyhow::Result<Material> {
    let mut rng = rand::rngs::OsRng;
    let mut key = match algorithm {
        SshAlgorithm::Ed25519 => PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519)
            .map_err(|e| keyward_core::fault!("err.sshKeyGenerate", "reason" => e))?,
        SshAlgorithm::Rsa4096 => {
            let pair = ssh_key::private::RsaKeypair::random(&mut rng, RSA_BITS)
                .map_err(|e| keyward_core::fault!("err.sshKeyGenerate", "reason" => e))?;
            PrivateKey::from(pair)
        }
    };
    key.set_comment(comment.trim());
    material(&key)
}

/// Read a private key a person pasted in: OpenSSH (with or without a
/// passphrase), or an RSA key in PEM (PKCS#1 `BEGIN RSA PRIVATE KEY`, PKCS#8
/// `BEGIN PRIVATE KEY`). The comment is kept when the key has one.
pub fn import(text: &str, passphrase: Option<&str>) -> anyhow::Result<Material> {
    let text = text.trim();
    if text.is_empty() {
        return Err(keyward_core::fault!("err.sshKeyEmpty"));
    }
    if text.starts_with("ssh-") || text.starts_with("ecdsa-") {
        // The public half: a common slip, and one worth naming.
        return Err(keyward_core::fault!("err.sshKeyIsPublic"));
    }
    if text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        let key = PrivateKey::from_openssh(text).map_err(|_| keyward_core::fault!("err.sshKeyUnreadable"))?;
        let key = if key.is_encrypted() {
            let Some(pass) = passphrase.filter(|p| !p.is_empty()) else {
                return Err(keyward_core::fault!("err.sshKeyNeedsPassphrase"));
            };
            key.decrypt(pass).map_err(|_| keyward_core::fault!("err.sshKeyWrongPassphrase"))?
        } else {
            key
        };
        return material(&key);
    }
    if text.contains("ENCRYPTED") {
        // A PEM key under a passphrase (`Proc-Type: 4,ENCRYPTED`, or
        // `BEGIN ENCRYPTED PRIVATE KEY`): its old ciphers are not worth
        // carrying; ssh-keygen converts it in one line.
        return Err(keyward_core::fault!("err.sshKeyPemEncrypted"));
    }
    if text.contains("-----BEGIN RSA PRIVATE KEY-----") || text.contains("-----BEGIN PRIVATE KEY-----") {
        use rsa::pkcs1::DecodeRsaPrivateKey as _;
        use rsa::pkcs8::DecodePrivateKey as _;
        let rsa = rsa::RsaPrivateKey::from_pkcs1_pem(text)
            .or_else(|_| rsa::RsaPrivateKey::from_pkcs8_pem(text))
            .map_err(|_| keyward_core::fault!("err.sshKeyUnsupported"))?;
        let pair = ssh_key::private::RsaKeypair::try_from(&rsa)
            .map_err(|_| keyward_core::fault!("err.sshKeyUnreadable"))?;
        return material(&PrivateKey::from(pair));
    }
    Err(keyward_core::fault!("err.sshKeyUnsupported"))
}

fn material(key: &PrivateKey) -> anyhow::Result<Material> {
    let private_key = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| keyward_core::fault!("err.sshKeyGenerate", "reason" => e))?;
    let public_key = key
        .public_key()
        .to_openssh()
        .map_err(|e| keyward_core::fault!("err.sshKeyGenerate", "reason" => e))?;
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    Ok(Material { private_key: Zeroizing::new(private_key.to_string()), public_key, fingerprint })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway keys made with ssh-keygen for these tests alone; the
    // fingerprints are what `ssh-keygen -lf` printed for them.
    const ED25519: &str = include_str!("../tests/fixtures/ssh/ed25519");
    const ED25519_LOCKED: &str = include_str!("../tests/fixtures/ssh/ed25519_locked");
    const RSA_PKCS1: &str = include_str!("../tests/fixtures/ssh/rsa_pkcs1");
    const RSA_PKCS8: &str = include_str!("../tests/fixtures/ssh/rsa_pkcs8");

    fn code(r: anyhow::Result<Material>) -> String {
        r.err().map(|e| e.to_string()).unwrap_or_default()
    }

    #[test]
    fn a_pasted_openssh_key_gives_the_fingerprint_ssh_keygen_gives() {
        let m = import(ED25519, None).unwrap();
        assert_eq!(m.fingerprint, "SHA256:/isoPc4zsyI5eGGgBTllIrgXx/hHi7HWN3AqKBECz5w");
        assert_eq!(
            m.public_key,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIACnh8bnnktS8RgGbWJqbI4+BOKen7uiuFML8UogMdp+ test@keyward"
        );
        assert!(m.private_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert_eq!(m.summary().algorithm, "ssh-ed25519");
    }

    #[test]
    fn a_key_under_a_passphrase_asks_for_it_and_is_stored_open() {
        assert!(code(import(ED25519_LOCKED, None)).starts_with("err.sshKeyNeedsPassphrase"));
        assert!(code(import(ED25519_LOCKED, Some("wrong"))).starts_with("err.sshKeyWrongPassphrase"));
        let m = import(ED25519_LOCKED, Some("hunter2")).unwrap();
        assert_eq!(m.fingerprint, "SHA256:7KUVCSm02vk1ukyAqFJkGjWpWhWUkla0TMAeoO0wHa8");
        // Stored without the passphrase: the agent has to be able to read it.
        assert!(!PrivateKey::from_openssh(m.private_key.as_str()).unwrap().is_encrypted());
    }

    #[test]
    fn rsa_keys_in_pem_are_normalised_into_openssh() {
        let one = import(RSA_PKCS1, None).unwrap();
        assert_eq!(one.fingerprint, "SHA256:tR70x1hZkzQ5uhFUie9wTgz8qHeuEh3LeN7j+8lizi4");
        assert!(one.private_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        let eight = import(RSA_PKCS8, None).unwrap();
        assert_eq!(eight.fingerprint, "SHA256:L1cTqEUTMHxe9NJo3/6hFf92vyHeJUWU86/D79EogJk");
        assert_eq!(eight.summary().algorithm, "ssh-rsa");
    }

    #[test]
    fn what_is_not_a_private_key_is_named() {
        assert!(code(import("  ", None)).starts_with("err.sshKeyEmpty"));
        assert!(code(import("ssh-ed25519 AAAA test", None)).starts_with("err.sshKeyIsPublic"));
        assert!(code(import("hello", None)).starts_with("err.sshKeyUnsupported"));
        let broken = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----";
        assert!(code(import(broken, None)).starts_with("err.sshKeyUnreadable"));
        let pem_locked = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n-----END RSA PRIVATE KEY-----";
        assert!(code(import(pem_locked, None)).starts_with("err.sshKeyPemEncrypted"));
    }

    #[test]
    fn a_generated_key_reads_back_to_the_same_fingerprint() {
        let m = generate(SshAlgorithm::Ed25519, "  laptop  ").unwrap();
        assert!(m.public_key.starts_with("ssh-ed25519 ") && m.public_key.ends_with(" laptop"));
        let again = import(&m.private_key, None).unwrap();
        assert_eq!(again.fingerprint, m.fingerprint);
        assert_eq!(again.public_key, m.public_key);
        // Two generations never give the same key.
        assert_ne!(generate(SshAlgorithm::Ed25519, "").unwrap().fingerprint, m.fingerprint);
    }
}
