//! Signing with a vault's ssh key. It lives in the daemon and nowhere else.
//!
//! The ssh plugin used to sign: it was built in, and the key lay in the same
//! memory as the vault. Now plugins are installed from the showcase and run as
//! separate processes, and the daemon does not give them the private key
//! (`entries` cuts it out). So the signing has to stay here: a plugin brings
//! the item, the data and the flags, and the key never leaves the daemon —
//! which is what keyward was written for.

use anyhow::Context as _;
use ssh_key::{PrivateKey, Signature};

/// The signature request's flags: a client asks for a particular RSA
/// variant.
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

/// Sign and hand the signature back in ssh's wire form — the algorithm name
/// and the bytes, exactly what the agent gives ssh.
pub fn sign(private_key: &str, data: &[u8], flags: u32) -> anyhow::Result<Vec<u8>> {
    use ssh_encoding::Encode as _;
    let key = PrivateKey::from_openssh(private_key)
        .map_err(|e| anyhow::anyhow!("the private key will not parse: {e}"))?;
    let signature = sign_with(&key, data, flags)?;
    let mut wire = Vec::new();
    signature.encode(&mut wire).context("the signature will not assemble into its wire form")?;
    Ok(wire)
}

/// Signing.
///
/// RSA is not here "just in case": the keys in real vaults are mostly 4096-bit
/// RSA, and without it the agent would show a key it cannot sign with. The
/// client picks the hash variant with flags; bare `ssh-rsa` (SHA-1) is left for
/// old servers that understand nothing else.
fn sign_with(key: &PrivateKey, data: &[u8], flags: u32) -> anyhow::Result<Signature> {
    use signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _};
    use ssh_key::private::KeypairData;

    match key.key_data() {
        // RSA is signed by hand: the client sets the hash variant with flags,
        // while the general `Signer` would pick one for every case. A modern
        // OpenSSH asks for rsa-sha2-512; old servers understand only
        // ssh-rsa.
        KeypairData::Rsa(pair) => {
            let p = rsa::BigUint::from_bytes_be(pair.private.p.as_bytes());
            let q = rsa::BigUint::from_bytes_be(pair.private.q.as_bytes());
            let e = rsa::BigUint::from_bytes_be(pair.public.e.as_bytes());
            let key = rsa::RsaPrivateKey::from_p_q(p, q, e)
                .map_err(|e| anyhow::anyhow!("the RSA key will not assemble: {e}"))?;
            let mut rng = rand::thread_rng();

            let (algorithm, bytes) = if flags & RSA_SHA2_512 != 0 {
                let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(key);
                let sig = signing
                    .try_sign_with_rng(&mut rng, data)
                    .map_err(|e| anyhow::anyhow!("signing failed: {e}"))?;
                ("rsa-sha2-512", sig.to_bytes())
            } else if flags & RSA_SHA2_256 != 0 {
                let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key);
                let sig = signing
                    .try_sign_with_rng(&mut rng, data)
                    .map_err(|e| anyhow::anyhow!("signing failed: {e}"))?;
                ("rsa-sha2-256", sig.to_bytes())
            } else {
                let signing = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new_unprefixed(key);
                let sig = signing
                    .try_sign_with_rng(&mut rng, data)
                    .map_err(|e| anyhow::anyhow!("signing failed: {e}"))?;
                ("ssh-rsa", sig.to_bytes())
            };

            let algorithm = ssh_key::Algorithm::new(algorithm)
                .map_err(|e| anyhow::anyhow!("an unknown algorithm: {e}"))?;
            Signature::new(algorithm, bytes).map_err(|e| anyhow::anyhow!("the signature will not assemble: {e}"))
        }

        // A hardware key is signed by the token itself, and we have none.
        KeypairData::SkEd25519(_) | KeypairData::SkEcdsaSha2NistP256(_) => {
            anyhow::bail!("the key lives in a hardware token; only the token can sign with it")
        }

        // Ed25519, ECDSA on every curve and DSA are signed by ssh-key itself.
        other => other
            .try_sign(data)
            .map_err(|e| anyhow::anyhow!("signing with a {:?} key failed: {e}", other.algorithm())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use signature::Verifier as _;
    use ssh_encoding::Decode as _;

    /// The round of a signature: the daemon signed, whoever holds the public
    /// half checked. That is the contract with ssh: a plugin gets bytes the
    /// server is obliged to accept.
    #[test]
    fn a_signature_round_trips_through_the_wire_form() {
        let key = PrivateKey::random(&mut rand::thread_rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let openssh = key.to_openssh(ssh_key::LineEnding::LF).unwrap();

        let wire = sign(&openssh, "who goes there".as_bytes(), 0).unwrap();
        let mut reader = wire.as_slice();
        let signature = Signature::decode(&mut reader).expect("the signature parses back");

        key.public_key().key_data().verify("who goes there".as_bytes(), &signature).expect("the signature did not check out");
        let wrong = key.public_key().key_data().verify("something else".as_bytes(), &signature);
        assert!(wrong.is_err(), "the signature fitted the wrong data");
    }

    #[test]
    fn a_broken_key_is_a_refusal_not_a_panic() {
        let e = sign("this is not a key", "data".as_bytes(), 0).unwrap_err().to_string();
        assert!(e.contains("will not parse"), "got: {e}");
    }
}
