//! Drafts of ssh keys: a key made or read in the daemon, waiting for its item
//! to be saved.
//!
//! The window used to receive a new private key, show it in a field, copy it
//! from JavaScript and send it back on save. A key that is only a draft now
//! stays here: the window is given a number, the public key and the
//! fingerprint, and the save names the draft by its number. The private key
//! is wiped when the draft is taken, when it runs out of time and when the
//! vault is locked.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use keyward_sshkey::Material;

/// Long enough to fill in an item's form, not long enough to be forgotten.
const TTL: Duration = Duration::from_secs(30 * 60);

static DRAFTS: Mutex<Option<HashMap<String, (Instant, Material)>>> = Mutex::new(None);

fn with_map<T>(f: impl FnOnce(&mut HashMap<String, (Instant, Material)>) -> T) -> T {
    let mut guard = DRAFTS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let map = guard.get_or_insert_with(HashMap::new);
    // The stale ones go first, whatever is asked.
    map.retain(|_, (made, _)| made.elapsed() < TTL);
    f(map)
}

/// Keeps a key and returns its number.
pub fn put(material: Material) -> String {
    let id = format!("{:032x}", rand::random::<u128>());
    with_map(|m| m.insert(id.clone(), (Instant::now(), material)));
    id
}

/// Takes a draft out, for sealing into an item: it is gone from here after.
pub fn take(id: &str) -> Option<Material> {
    with_map(|m| m.remove(id).map(|(_, material)| material))
}

/// Does something with a draft's key in place — copy it, for instance.
pub fn with<T>(id: &str, f: impl FnOnce(&Material) -> T) -> Option<T> {
    with_map(|m| m.get(id).map(|(_, material)| f(material)))
}

/// Forgets every draft: the vault was locked.
pub fn clear() {
    with_map(HashMap::clear);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_is_taken_once_and_forgotten_on_lock() {
        let key = keyward_sshkey::generate(keyward_core::edits::SshAlgorithm::Ed25519, "").unwrap();
        let public = key.public_key.clone();
        let id = put(key);
        assert_eq!(with(&id, |m| m.public_key.clone()), Some(public));
        assert!(take(&id).is_some());
        assert!(take(&id).is_none(), "a draft is taken once");
        let again = put(keyward_sshkey::generate(keyward_core::edits::SshAlgorithm::Ed25519, "").unwrap());
        clear();
        assert!(take(&again).is_none(), "a lock forgets every draft");
    }
}
