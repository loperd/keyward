//! The account fingerprint: the five words Bitwarden shows in its settings,
//! by which the owner of an organisation checks that they are confirming that
//! very member and not a substituted key.
//!
//! The official client's algorithm, with no departures: otherwise the words
//! would not match what a person sees in the web interface, and the check
//! would mean nothing.
//!
//! `keyFingerprint = SHA-256(DER of the public key)`, then
//! `HKDF-Expand(prk = keyFingerprint, info = userId, 32 bytes)`, and the
//! number those bytes make is written out in base 7776 — the size of the EFF
//! list.

use sha2::{Digest as _, Sha256};

/// The whole EFF list: lines like `11111\tabacus`, the word after the tab.
const WORDLIST: &str = include_str!("eff_large_wordlist.txt");

/// How many words a fingerprint has. Bitwarden wants 64 bits of entropy; a
/// word out of a list of 7776 gives about 12.9, so five words are enough and
/// four are not.
const WORDS: usize = 5;

fn words() -> &'static [&'static str] {
    static LIST: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    LIST.get_or_init(|| {
        WORDLIST
            .lines()
            .filter_map(|l| l.split('\t').nth(1))
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .collect()
    })
}

/// The whole EFF list, checked: a passphrase out of a damaged one would be
/// weaker than it looks.
pub fn wordlist() -> anyhow::Result<&'static [&'static str]> {
    let list = words();
    if list.len() != 7776 {
        anyhow::bail!("the word list is damaged: {} lines instead of 7776", list.len());
    }
    Ok(list)
}

/// Five words from the user identifier and the DER (SPKI) of the public key.
pub fn phrase(user_id: &str, public_key_der: &[u8]) -> anyhow::Result<Vec<String>> {
    let list = words();
    if list.len() != 7776 {
        anyhow::bail!("the word list is damaged: {} lines instead of 7776", list.len());
    }
    let prk = Sha256::digest(public_key_der);
    let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|e| anyhow::anyhow!("HKDF did not take the key fingerprint: {e}"))?;
    let mut material = [0u8; 32];
    hkdf.expand(user_id.as_bytes(), &mut material)
        .map_err(|e| anyhow::anyhow!("HKDF: {e}"))?;

    let mut number = material.to_vec();
    let base = list.len() as u32;
    let mut out = Vec::with_capacity(WORDS);
    for _ in 0..WORDS {
        let rem = divmod_in_place(&mut number, base);
        out.push(list[rem as usize].to_string());
    }
    Ok(out)
}

/// A member's public key as the server hands it out (base64 of the DER), parsed,
/// with the five words it makes for them: what the owner compares with the
/// member before confirming, and the key the organisation key is then sealed to.
pub fn member_key(user_id: &str, public_b64: &str) -> anyhow::Result<(rsa::RsaPublicKey, Vec<String>)> {
    use base64::Engine as _;
    use rsa::pkcs8::DecodePublicKey as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(public_b64.trim())
        .map_err(|e| keyward_core::fault!("err.memberKeyNotBase64", "reason" => e))?;
    let public = rsa::RsaPublicKey::from_public_key_der(&der)
        .map_err(|e| keyward_core::fault!("err.memberKeyUnparsable", "reason" => e))?;
    let words = phrase(user_id, &der)?;
    Ok((public, words))
}

/// A refusal unless the words the person was shown are the words of the key
/// about to be sealed to: a key swapped between the two is not trusted.
pub fn ensure_shown(shown: &[String], now: &[String]) -> anyhow::Result<()> {
    if shown.len() != WORDS || shown != now {
        return Err(keyward_core::fault!("err.fingerprintChanged"));
    }
    Ok(())
}

/// Divides a big-endian number in place by `divisor` and returns the
/// remainder. Written out rather than pulling in a big-integer crate: 32 bytes
/// and five divisions are not worth one.
fn divmod_in_place(number: &mut [u8], divisor: u32) -> u32 {
    let mut carry: u64 = 0;
    for byte in number.iter_mut() {
        let cur = (carry << 8) | u64::from(*byte);
        *byte = (cur / u64::from(divisor)) as u8;
        carry = cur % u64::from(divisor);
    }
    carry as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_list_is_whole() {
        let list = words();
        assert_eq!(list.len(), 7776);
        assert_eq!(list[0], "abacus");
        assert_eq!(list[7775], "zoom");
        assert!(list.iter().all(|w| w.chars().all(|c| c.is_ascii_lowercase() || c == '-')));
    }

    #[test]
    fn a_fingerprint_is_deterministic_and_five_words_long() {
        let der = vec![7u8; 294];
        let a = phrase("user", &der).expect("a fingerprint");
        let b = phrase("user", &der).expect("a fingerprint");
        assert_eq!(a, b);
        assert_eq!(a.len(), 5);
        let list = words();
        assert!(a.iter().all(|w| list.contains(&w.as_str())), "words outside the list: {a:?}");
    }

    #[test]
    fn it_matches_an_independent_calculation() {
        // Computed in Python (hashlib + hmac): SHA-256 over 512 bytes of
        // 0x00..0xFF twice, HKDF-Expand with info = userId, five divisions by
        // 7776. Checking against a calculation done elsewhere is the only way
        // to catch a swapped byte order or salt.
        let der: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let words = phrase("11111111-2222-3333-4444-555555555555", &der).expect("a fingerprint");
        assert_eq!(words, ["preamble", "dispersed", "spree", "doorknob", "stable"]);
    }

    /// Bitwarden's own known answer (sdk-internal,
    /// crates/bitwarden-crypto/src/fingerprint.rs, `test_fingerprint`): the
    /// words the official clients show for this user and this key.
    const BW_USER: &str = "a09726a0-9590-49d1-a5f5-afe300b6a515";
    const BW_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuyYs8W7NWf0Zv35Ueco93730dtRKi4Jhc6Snar+86drE+ruSfaCWMcbgsAoAj2Pm6KAzaJrTIVCqBERQ23OncpzjfcGAeyf+v3w/gSw/EjihMJ4AG5ICY4hLFYcGdgwa+7is+TVO0i6PEWjKQa3l2+mQo2XY7pg2ngHDMssV4gxSqq+qoBX3+FBhewCYdOV+3cebwsAzz7HwoFTxKViwNW8crbHonhZPhZgfIAzEkzo5MvzQg5azhLKW6vuPfaOQFC5HqPykVnh8OPzO0uzUi3+97CguAu4N2CgwVYXltZuw2fGamdVw3kjbxQPbOE1tL0j7gyTwYKkfUl2m8gMh1QIDAQAB";

    #[test]
    fn it_matches_bitwardens_known_answer() {
        let (_, words) = member_key(BW_USER, BW_KEY).expect("the member's key");
        assert_eq!(words, ["turban", "deftly", "anime", "chatroom", "unselfish"]);
    }

    #[test]
    fn a_member_key_that_is_not_one_is_refused() {
        let e = member_key(BW_USER, "not base64!").unwrap_err();
        assert!(e.to_string().starts_with("err.memberKeyNotBase64"), "{e}");
        let e = member_key(BW_USER, "Z2FyYmFnZQ==").unwrap_err();
        assert!(e.to_string().starts_with("err.memberKeyUnparsable"), "{e}");
    }

    #[test]
    fn the_words_shown_must_be_the_words_of_the_key_sealed_to() {
        let (_, now) = member_key(BW_USER, BW_KEY).unwrap();
        ensure_shown(&now, &now).expect("the same words pass");
        let mut other = now.clone();
        other[4] = "zoom".into();
        assert_eq!(ensure_shown(&other, &now).unwrap_err().to_string(), "err.fingerprintChanged");
        assert_eq!(ensure_shown(&[], &now).unwrap_err().to_string(), "err.fingerprintChanged");
        // Another user's words for the very same key are not this member's.
        let (_, theirs) = member_key("someone-else", BW_KEY).unwrap();
        assert_eq!(ensure_shown(&theirs, &now).unwrap_err().to_string(), "err.fingerprintChanged");
    }

    #[test]
    fn another_user_or_key_gives_other_words() {
        let der = vec![1u8; 100];
        let a = phrase("alice", &der).unwrap();
        let b = phrase("bob", &der).unwrap();
        let c = phrase("alice", &[2u8; 100]).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn dividing_in_place_counts_like_ordinary_division() {
        // 0x01_00_00 = 65536; 65536 / 7776 = 8, remainder 3328.
        let mut n = vec![0x01, 0x00, 0x00];
        assert_eq!(divmod_in_place(&mut n, 7776), 3328);
        assert_eq!(n, vec![0, 0, 8]);
    }
}
