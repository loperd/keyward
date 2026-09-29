//! Bitwarden's cryptography.
//!
//! Written over RustCrypto's generic crates rather than borrowed from somebody
//! else's library: the format is documented and fits into a couple of hundred
//! lines, and the project is left without a dependency it would have to carry
//! whole for the sake of three files.
//!
//! What is here:
//! * deriving the master key from the password (PBKDF2-SHA256 and Argon2id);
//! * stretching the master key into an encryption/mac pair through HKDF;
//! * parsing strings of the form `2.iv|ct|mac` (AES-256-CBC + HMAC), and
//!   writing them back;
//! * decrypting organisation keys with an RSA private key.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::Engine as _;
use hmac::{Mac as _, SimpleHmac};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, ZeroizeOnDrop};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = SimpleHmac<Sha256>;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The kind of key derivation function, as the server reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Kdf {
    Pbkdf2 { iterations: u32 },
    Argon2id { iterations: u32, memory_mib: u32, parallelism: u32 },
}

/// A pair of keys: one encrypts, the other signs.
///
/// Zeroed when dropped: a key left in freed memory is a key somebody will one
/// day find in a dump.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl SymmetricKey {
    /// Out of 64 bytes: the first 32 encrypt, the second 32 sign.
    pub fn from_bytes(raw: &[u8]) -> anyhow::Result<Self> {
        if raw.len() != 64 {
            anyhow::bail!("a key must be 64 bytes; got {}", raw.len());
        }
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        enc.copy_from_slice(&raw[..32]);
        mac.copy_from_slice(&raw[32..]);
        Ok(Self { enc, mac })
    }
}

/// The master key: 32 bytes derived from the password.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Derives the master key from the password and the login.
    ///
    /// The salt is the login in lower case: the protocol says so, and
    /// compatibility with the official clients depends on it.
    pub fn derive(password: &str, email: &str, kdf: Kdf) -> anyhow::Result<Self> {
        let email = email.trim().to_lowercase();
        let mut out = [0u8; 32];

        match kdf {
            Kdf::Pbkdf2 { iterations } => {
                pbkdf2::pbkdf2::<HmacSha256>(password.as_bytes(), email.as_bytes(), iterations, &mut out)
                    .map_err(|e| anyhow::anyhow!("PBKDF2 did not finish: {e}"))?;
            }
            Kdf::Argon2id { iterations, memory_mib, parallelism } => {
                // Argon2's salt is not the login itself but its SHA-256: the
                // salt has a fixed length and logins have any.
                let salt = Sha256::digest(email.as_bytes());
                let params = argon2::Params::new(memory_mib * 1024, iterations, parallelism, Some(32))
                    .map_err(|e| anyhow::anyhow!("the Argon2 parameters are wrong: {e}"))?;
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(password.as_bytes(), &salt, &mut out)
                    .map_err(|e| anyhow::anyhow!("Argon2 did not finish: {e}"))?;
            }
        }

        Ok(Self(out))
    }

    /// The password hash that goes to the server at login. One iteration over
    /// the master key: the server must not be able to derive the key itself
    /// from it.
    pub fn password_hash(&self, password: &str) -> String {
        let mut out = [0u8; 32];
        let _ = pbkdf2::pbkdf2::<HmacSha256>(&self.0, password.as_bytes(), 1, &mut out);
        B64.encode(out)
    }

    /// Stretches the master key into an encryption/mac pair.
    ///
    /// It is this pair that decrypts the protected key; the master key itself
    /// opens none of the vault's contents.
    pub fn stretch(&self) -> anyhow::Result<SymmetricKey> {
        let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&self.0)
            .map_err(|e| anyhow::anyhow!("HKDF did not take the key: {e}"))?;
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        hkdf.expand(b"enc", &mut enc).map_err(|e| anyhow::anyhow!("HKDF: {e}"))?;
        hkdf.expand(b"mac", &mut mac).map_err(|e| anyhow::anyhow!("HKDF: {e}"))?;
        Ok(SymmetricKey { enc, mac })
    }
}

/// An encrypted string of the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncString {
    /// `2.iv|ct|mac`: AES-256-CBC with an HMAC-SHA256 mac.
    Symmetric { iv: Vec<u8>, ct: Vec<u8>, mac: Vec<u8> },
    /// `4.ct` or `6.ct`: RSA-OAEP.
    Asymmetric { ct: Vec<u8>, sha256: bool },
}

impl EncString {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let (ty, rest) = s
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("the string does not look like a ciphertext"))?;
        let decode = |v: &str| B64.decode(v).map_err(|e| anyhow::anyhow!("not base64: {e}"));

        match ty {
            "2" => {
                let mut parts = rest.split('|');
                let (Some(iv), Some(ct), Some(mac)) = (parts.next(), parts.next(), parts.next()) else {
                    anyhow::bail!("a type 2 ciphertext has to have three parts");
                };
                Ok(Self::Symmetric { iv: decode(iv)?, ct: decode(ct)?, mac: decode(mac)? })
            }
            "4" => Ok(Self::Asymmetric { ct: decode(rest)?, sha256: false }),
            "6" => Ok(Self::Asymmetric { ct: decode(rest)?, sha256: true }),
            other => anyhow::bail!("ciphertext type {other} is not supported"),
        }
    }

    /// Decrypting with a symmetric key.
    ///
    /// The mac is checked **before** decryption and in constant time:
    /// otherwise a forged ciphertext could be found by timing the answer.
    pub fn decrypt(&self, key: &SymmetricKey) -> anyhow::Result<Vec<u8>> {
        let Self::Symmetric { iv, ct, mac } = self else {
            anyhow::bail!("a symmetric ciphertext is needed");
        };

        let mut hmac = HmacSha256::new_from_slice(&key.mac)
            .map_err(|e| anyhow::anyhow!("HMAC did not take the key: {e}"))?;
        hmac.update(iv);
        hmac.update(ct);
        let expected = hmac.finalize().into_bytes();
        if expected.ct_eq(mac).unwrap_u8() != 1 {
            anyhow::bail!("the mac does not match: a wrong key or a forgery");
        }

        Aes256CbcDec::new_from_slices(&key.enc, iv)
            .map_err(|e| anyhow::anyhow!("AES did not take the key: {e}"))?
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))
    }

    /// Encrypting with a symmetric key.
    pub fn encrypt(key: &SymmetricKey, plaintext: &[u8]) -> anyhow::Result<Self> {
        use rsa::rand_core::RngCore as _;
        let mut iv = [0u8; 16];
        rsa::rand_core::OsRng.fill_bytes(&mut iv);

        let ct = Aes256CbcEnc::new_from_slices(&key.enc, &iv)
            .map_err(|e| anyhow::anyhow!("AES did not take the key: {e}"))?
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        let mut hmac = HmacSha256::new_from_slice(&key.mac)
            .map_err(|e| anyhow::anyhow!("HMAC did not take the key: {e}"))?;
        hmac.update(&iv);
        hmac.update(&ct);

        Ok(Self::Symmetric {
            iv: iv.to_vec(),
            ct,
            mac: hmac.finalize().into_bytes().to_vec(),
        })
    }

    /// Decrypting with an RSA private key: that is how organisation keys
    /// arrive.
    pub fn decrypt_rsa(&self, private_key: &rsa::RsaPrivateKey) -> anyhow::Result<Vec<u8>> {
        let Self::Asymmetric { ct, sha256 } = self else {
            anyhow::bail!("an asymmetric ciphertext is needed");
        };
        let padding = if *sha256 {
            rsa::Oaep::new::<Sha256>()
        } else {
            rsa::Oaep::new::<sha1::Sha1>()
        };
        private_key
            .decrypt(padding, ct)
            .map_err(|e| anyhow::anyhow!("RSA did not decrypt: {e}"))
    }
}

impl std::fmt::Display for EncString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symmetric { iv, ct, mac } => {
                write!(f, "2.{}|{}|{}", B64.encode(iv), B64.encode(ct), B64.encode(mac))
            }
            Self::Asymmetric { ct, sha256 } => {
                write!(f, "{}.{}", if *sha256 { 6 } else { 4 }, B64.encode(ct))
            }
        }
    }
}

/// Encrypts data with a public key: that is how an organisation gets its
/// key.
///
/// Type 4 in Bitwarden's terms: RSA-OAEP with SHA-1. The hash is not our
/// choice, the protocol says so, and changing it unilaterally is not allowed:
/// the official clients would not read what we wrote.
pub fn encrypt_rsa(public_key: &rsa::RsaPublicKey, data: &[u8]) -> anyhow::Result<String> {
    use base64::Engine as _;
    use rsa::Oaep;

    // OsRng rather than thread_rng: the generation is called from an async
    // task, and thread_rng is not Send and does not cross a task boundary.
    let mut rng = rand::rngs::OsRng;
    let padding = Oaep::new::<sha1::Sha1>();
    let sealed = public_key
        .encrypt(&mut rng, padding, data)
        .map_err(|e| anyhow::anyhow!("the organisation key will not encrypt: {e}"))?;
    Ok(format!("4.{}", base64::engine::general_purpose::STANDARD.encode(sealed)))
}

/// Parses the user's private key: it lies in the vault encrypted.
pub fn parse_private_key(der: &[u8]) -> anyhow::Result<rsa::RsaPrivateKey> {
    use rsa::pkcs8::DecodePrivateKey as _;
    rsa::RsaPrivateKey::from_pkcs8_der(der)
        .map_err(|e| anyhow::anyhow!("the private key will not parse: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymmetricKey {
        SymmetricKey::from_bytes(&[7u8; 64]).unwrap()
    }

    #[test]
    fn round_trip_survives_text_and_binary() {
        for data in [b"".as_slice(), b"secret".as_slice(), &[0u8, 255, 13, 10, 200]] {
            let enc = EncString::encrypt(&key(), data).unwrap();
            assert_eq!(enc.decrypt(&key()).unwrap(), data);
        }
    }

    #[test]
    fn wrong_key_is_rejected_by_signature_not_by_garbage() {
        let enc = EncString::encrypt(&key(), b"secret").unwrap();
        let other = SymmetricKey::from_bytes(&[9u8; 64]).unwrap();
        // It matters that the error comes from the mac check: decrypting with
        // somebody else's key and getting rubbish would be far worse.
        let err = enc.decrypt(&other).unwrap_err().to_string();
        assert!(err.contains("mac"), "an unexpected error: {err}");
    }

    #[test]
    fn tampering_with_ciphertext_is_detected() {
        let mut enc = EncString::encrypt(&key(), b"secret").unwrap();
        if let EncString::Symmetric { ct, .. } = &mut enc {
            ct[0] ^= 1;
        }
        assert!(enc.decrypt(&key()).is_err());
    }

    #[test]
    fn text_form_round_trips() {
        let enc = EncString::encrypt(&key(), b"hello").unwrap();
        let text = enc.to_string();
        assert!(text.starts_with("2."));
        assert_eq!(EncString::parse(&text).unwrap(), enc);
    }

    #[test]
    fn malformed_strings_are_rejected() {
        for bad in ["", "hello", "2.only-one-part", "9.abc"] {
            assert!(EncString::parse(bad).is_err(), "must be refused: {bad:?}");
        }
    }

    #[test]
    fn pbkdf2_matches_an_independent_implementation() {
        // The values were computed by another implementation of
        // PBKDF2-HMAC-SHA256 (hashlib in Python) for the password `password`,
        // the login `nobody@example.com` and 100000 iterations. Checking
        // against a calculation done elsewhere is the only way to catch a
        // mistake in the order of arguments or in the salt: an implementation
        // of one's own will "agree with itself" even with them swapped.
        let mk = MasterKey::derive(
            "password",
            "nobody@example.com",
            Kdf::Pbkdf2 { iterations: 100_000 },
        )
        .unwrap();
        assert_eq!(B64.encode(mk.0), "QVBMpLXA72bJyjN3kbRvA0ipNCz9FkPjA2jmqUUzA8Q=");
        assert_eq!(mk.password_hash("password"), "9l0bhF2MScUS3qI2Ty/FbiQWgf7rU9s9TyO1BdX6TVc=");
    }

    #[test]
    fn email_case_and_spaces_do_not_change_the_key() {
        let a = MasterKey::derive("p", "User@Example.COM", Kdf::Pbkdf2 { iterations: 1000 }).unwrap();
        let b = MasterKey::derive("p", "  user@example.com  ", Kdf::Pbkdf2 { iterations: 1000 }).unwrap();
        assert_eq!(a.0, b.0);
    }

    #[test]
    fn stretched_halves_differ() {
        let mk = MasterKey::derive("p", "u@e.com", Kdf::Pbkdf2 { iterations: 1000 }).unwrap();
        let k = mk.stretch().unwrap();
        assert_ne!(k.enc, k.mac, "the encryption key and the mac key must differ");
    }
}
