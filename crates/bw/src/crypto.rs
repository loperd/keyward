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

/// The KDF parameters keyward derives a key with, wherever they come from: the
/// server's prelogin answer, the session on disk, or a change the person asks
/// for. A server (or whoever stands in for it) that answers with one PBKDF2
/// iteration makes the password hash it then receives cheap to brute-force;
/// one that answers with a terabyte of Argon2 memory hangs the daemon. Both
/// are refused before the password is touched.
///
/// The upper bounds and PBKDF2's floor are Vaultwarden's. Argon2's floors are
/// stricter than Vaultwarden's (1 iteration, 15 MiB): Bitwarden's own clients
/// refuse below 2 iterations and 16 MiB, and so does keyward.
pub const PBKDF2_ITERATIONS: std::ops::RangeInclusive<u32> = 100_000..=2_000_000;
pub const ARGON2_ITERATIONS: std::ops::RangeInclusive<u32> = 2..=10;
pub const ARGON2_MEMORY_MIB: std::ops::RangeInclusive<u32> = 16..=1024;
pub const ARGON2_PARALLELISM: std::ops::RangeInclusive<u32> = 1..=16;

/// The dictionary key a refused set of KDF parameters is reported with.
pub const KDF_OUT_OF_RANGE: &str = "err.kdfOutOfRange";

/// Which bound a set of KDF parameters breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfBound {
    Pbkdf2Iterations,
    Argon2Iterations,
    Argon2Memory,
    Argon2Parallelism,
}

/// KDF parameters outside [`PBKDF2_ITERATIONS`] and the Argon2 bounds.
///
/// Displayed as the bare dictionary key, so the daemon hands it to the window
/// unchanged and the window writes the sentence; `bound` says which limit it
/// was, for a caller that wants a more precise word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfOutOfRange {
    pub bound: KdfBound,
}

impl std::fmt::Display for KdfOutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(KDF_OUT_OF_RANGE)
    }
}

impl std::error::Error for KdfOutOfRange {}

impl Kdf {
    /// The parameters, if they are within keyward's bounds.
    pub fn checked(self) -> Result<Self, KdfOutOfRange> {
        let broken = match self {
            Kdf::Pbkdf2 { iterations } => (!PBKDF2_ITERATIONS.contains(&iterations)).then_some(KdfBound::Pbkdf2Iterations),
            Kdf::Argon2id { iterations, memory_mib, parallelism } => {
                if !ARGON2_ITERATIONS.contains(&iterations) {
                    Some(KdfBound::Argon2Iterations)
                } else if !ARGON2_MEMORY_MIB.contains(&memory_mib) {
                    Some(KdfBound::Argon2Memory)
                } else if !ARGON2_PARALLELISM.contains(&parallelism) {
                    Some(KdfBound::Argon2Parallelism)
                } else {
                    None
                }
            }
        };
        match broken {
            Some(bound) => Err(KdfOutOfRange { bound }),
            None => Ok(self),
        }
    }
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
    /// `3.ct` (RSA-OAEP with SHA-256) or `4.ct` (RSA-OAEP with SHA-1).
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
            // Bitwarden's numbering: 3 is Rsa2048_OaepSha256_B64, 4 is
            // Rsa2048_OaepSha1_B64. Type 6 used to be read here as OAEP-SHA256,
            // which it is not: it is the SHA-1 variant with a mac appended.
            "3" => Ok(Self::Asymmetric { ct: decode(rest)?, sha256: true }),
            "4" => Ok(Self::Asymmetric { ct: decode(rest)?, sha256: false }),
            // 5 (Rsa2048_OaepSha256_HmacSha256_B64) and 6
            // (Rsa2048_OaepSha1_HmacSha256_B64) are deprecated by Bitwarden and
            // carry an HMAC under a key the recipient of an RSA ciphertext
            // never has: the official clients drop the mac unchecked. Reading
            // them would mean accepting a mac we cannot verify, so they are
            // refused by name rather than half-supported.
            "5" | "6" => anyhow::bail!("ciphertext type {ty} (RSA with an HMAC) is deprecated and not accepted: its mac cannot be verified"),
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
                write!(f, "{}.{}", if *sha256 { 3 } else { 4 }, B64.encode(ct))
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
    fn bitwarden_default_kdfs_are_accepted() {
        let pbkdf2 = Kdf::Pbkdf2 { iterations: 600_000 };
        assert_eq!(pbkdf2.checked(), Ok(pbkdf2));
        let argon2 = Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 4 };
        assert_eq!(argon2.checked(), Ok(argon2));
        // The edges themselves are inside.
        assert!(Kdf::Pbkdf2 { iterations: 100_000 }.checked().is_ok());
        assert!(Kdf::Pbkdf2 { iterations: 2_000_000 }.checked().is_ok());
        assert!(Kdf::Argon2id { iterations: 2, memory_mib: 16, parallelism: 1 }.checked().is_ok());
        assert!(Kdf::Argon2id { iterations: 10, memory_mib: 1024, parallelism: 16 }.checked().is_ok());
    }

    #[test]
    fn weak_and_huge_kdfs_are_refused() {
        let bound = |kdf: Kdf| kdf.checked().unwrap_err().bound;
        // A downgrade: a password hash a server could brute-force.
        assert_eq!(bound(Kdf::Pbkdf2 { iterations: 1 }), KdfBound::Pbkdf2Iterations);
        assert_eq!(bound(Kdf::Pbkdf2 { iterations: 99_999 }), KdfBound::Pbkdf2Iterations);
        assert_eq!(bound(Kdf::Argon2id { iterations: 1, memory_mib: 64, parallelism: 4 }), KdfBound::Argon2Iterations);
        assert_eq!(bound(Kdf::Argon2id { iterations: 3, memory_mib: 15, parallelism: 4 }), KdfBound::Argon2Memory);
        assert_eq!(bound(Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 0 }), KdfBound::Argon2Parallelism);
        // A denial of service: work or memory the daemon would hang on.
        assert_eq!(bound(Kdf::Pbkdf2 { iterations: u32::MAX }), KdfBound::Pbkdf2Iterations);
        assert_eq!(bound(Kdf::Argon2id { iterations: 11, memory_mib: 64, parallelism: 4 }), KdfBound::Argon2Iterations);
        assert_eq!(bound(Kdf::Argon2id { iterations: 3, memory_mib: 1025, parallelism: 4 }), KdfBound::Argon2Memory);
        assert_eq!(bound(Kdf::Argon2id { iterations: 3, memory_mib: 64, parallelism: 17 }), KdfBound::Argon2Parallelism);
        // The window reads the key.
        assert_eq!(Kdf::Pbkdf2 { iterations: 1 }.checked().unwrap_err().to_string(), KDF_OUT_OF_RANGE);
    }

    /// One key for the RSA tests: generating 2048 bits is slow in a debug build.
    fn rsa_key() -> &'static rsa::RsaPrivateKey {
        static KEY: std::sync::OnceLock<rsa::RsaPrivateKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap())
    }

    #[test]
    fn type_4_is_oaep_sha1_and_reads_what_we_write() {
        let private = rsa_key();
        let sealed = encrypt_rsa(&rsa::RsaPublicKey::from(private), b"org key").unwrap();
        let parsed = EncString::parse(&sealed).unwrap();
        assert!(matches!(parsed, EncString::Asymmetric { sha256: false, .. }));
        assert_eq!(parsed.decrypt_rsa(private).unwrap(), b"org key");
        assert_eq!(parsed.to_string(), sealed);
    }

    #[test]
    fn type_3_is_oaep_sha256() {
        let private = rsa_key();
        let ct = rsa::RsaPublicKey::from(private)
            .encrypt(&mut rand::rngs::OsRng, rsa::Oaep::new::<Sha256>(), b"org key")
            .unwrap();
        let text = format!("3.{}", B64.encode(&ct));
        let parsed = EncString::parse(&text).unwrap();
        assert!(matches!(parsed, EncString::Asymmetric { sha256: true, .. }));
        assert_eq!(parsed.decrypt_rsa(private).unwrap(), b"org key");
        // It is written back as 3, not as the 6 it used to be mislabelled as.
        assert_eq!(parsed.to_string(), text);
    }

    #[test]
    fn rsa_with_an_hmac_is_refused_by_name() {
        // 6 was once read as OAEP-SHA256; it is OAEP-SHA1 with a mac we have
        // no key to check. 5 is the SHA-256 one. Neither is accepted.
        for value in ["5.Y3Q=|bWFj", "6.Y3Q=|bWFj", "6.Y3Q="] {
            let err = EncString::parse(value).unwrap_err().to_string();
            assert!(err.contains("deprecated"), "{value}: {err}");
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
