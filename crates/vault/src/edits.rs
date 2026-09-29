//! The queue of edits on disk.
//!
//! A file holds the whole item in the shape it will be sent to the server —
//! with **every value already encrypted** — plus its previous version so that
//! it can be rolled back. What the list of edits shows about it (the item's
//! name, the captions of the changed fields, the date, the last error) is
//! sealed with the account's user key as well: none of it is in the clear.
//!
//! In the clear there is only what is needed while the vault is locked: a
//! random identifier (the file's name), a hash of the account (so that each
//! vault finds its own edits and never takes another's), whether the edit is
//! still waiting to be sent, and the two versions of the item, which are the
//! server's own shape and carry nothing the snapshot does not.
//!
//! Files of the old shape — with the name and the account's email in the
//! clear — are still read, and are rewritten sealed as soon as their vault is
//! opened.

use keyward_core::edits::{ChangedField, EditState, PendingEdit};

use crate::read::Ring;

/// An edit as the code works with it: its metadata plus two versions of the
/// item.
pub struct StoredEdit {
    pub meta: PendingEdit,
    /// What is being sent.
    pub next: keyward_bw::model::Cipher,
    /// What was there before the edit, for rolling back.
    pub previous: keyward_bw::model::Cipher,
}

/// An edit's file.
#[derive(serde::Serialize, serde::Deserialize)]
struct Disk {
    id: String,
    /// `paths::account_key` of the account the edit belongs to.
    account: String,
    /// Still waiting to be sent: counted and retried while the vault is
    /// locked too.
    waiting: bool,
    /// `Sealed`, encrypted with the account's user key.
    sealed: String,
    next: keyward_bw::model::Cipher,
    previous: keyward_bw::model::Cipher,
}

/// What `Disk::sealed` opens into.
#[derive(serde::Serialize, serde::Deserialize)]
struct Sealed {
    account_id: String,
    entry_id: String,
    entry_name: String,
    created_at: String,
    changed: Vec<ChangedField>,
    state: EditState,
}

/// The shape files had before sealing.
#[derive(serde::Deserialize)]
struct Legacy {
    #[serde(flatten)]
    meta: PendingEdit,
    next: keyward_bw::model::Cipher,
    previous: keyward_bw::model::Cipher,
}

enum OnDisk {
    Sealed(Disk),
    Legacy(Legacy),
    /// There, but unreadable: it is not quietly skipped.
    Damaged(String),
}

fn parse(text: &str) -> Option<OnDisk> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    if value.get("sealed").is_some() {
        serde_json::from_value(value).ok().map(OnDisk::Sealed)
    } else {
        serde_json::from_value(value).ok().map(OnDisk::Legacy)
    }
}

/// How many edits that are done with (sent or rolled back) are kept for
/// rolling back; the oldest beyond it are deleted.
const KEEP_DONE: usize = 50;

fn dir() -> std::path::PathBuf {
    keyward_core::paths::base_dir().join("edits")
}

fn path(id: &str) -> std::path::PathBuf {
    // We make the identifier ourselves, but guarding against it costs less
    // than writing a file into the wrong place once.
    let safe: String = id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    dir().join(format!("{safe}.json"))
}

fn files() -> Vec<(std::path::PathBuf, OnDisk)> {
    let entries = match std::fs::read_dir(dir()) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::error!(error = %e, "the directory of edits cannot be read");
            return Vec::new();
        }
    };
    entries
        .filter_map(|e| match e {
            Ok(e) => Some(e.path()),
            Err(e) => {
                tracing::error!(error = %e, "an entry of the edits directory cannot be read");
                None
            }
        })
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let id = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let parsed = match std::fs::read_to_string(&p) {
                Ok(text) => parse(&text),
                Err(e) => {
                    tracing::error!(error = %e, edit = %id, "an edit cannot be read");
                    None
                }
            };
            let parsed = parsed.unwrap_or_else(|| {
                tracing::error!(edit = %id, "an edit is damaged");
                OnDisk::Damaged(id)
            });
            (p, parsed)
        })
        .collect()
}

fn seal(ring: &Ring<'_>, meta: &PendingEdit) -> anyhow::Result<String> {
    let sealed = Sealed {
        account_id: meta.account_id.clone(),
        entry_id: meta.entry_id.clone(),
        entry_name: meta.entry_name.clone(),
        created_at: meta.created_at.clone(),
        changed: meta.changed.clone(),
        state: meta.state.clone(),
    };
    let plain = zeroize::Zeroizing::new(serde_json::to_string(&sealed)?);
    crate::read::encrypt_blob(ring, &plain)
}

/// Opens an edit with the account's key. `Ok(None)` if it is another
/// account's; an error if it is this account's and does not open — that is
/// damage, not somebody else's edit.
fn open(ring: &Ring<'_>, account_id: &str, disk: &Disk) -> anyhow::Result<Option<PendingEdit>> {
    if disk.account != keyward_core::paths::account_key(account_id) {
        return Ok(None);
    }
    let damaged = || {
        tracing::error!(edit = %disk.id, "an edit of this account does not open with its key");
        keyward_core::fault!("err.editDamaged")
    };
    let plain = zeroize::Zeroizing::new(crate::read::decrypt_blob(ring, &disk.sealed).ok_or_else(damaged)?);
    let s: Sealed = serde_json::from_str(&plain).map_err(|_| damaged())?;
    if s.account_id != account_id {
        return Err(damaged());
    }
    Ok(Some(PendingEdit {
        id: disk.id.clone(),
        account_id: s.account_id,
        entry_id: s.entry_id,
        entry_name: s.entry_name,
        created_at: s.created_at,
        changed: s.changed,
        state: s.state,
        locked: false,
        damaged: false,
    }))
}

/// What the list shows of an edit whose vault is locked: that it is there
/// and whether it waits, nothing more.
fn locked(disk: &Disk) -> PendingEdit {
    PendingEdit {
        id: disk.id.clone(),
        account_id: String::new(),
        entry_id: String::new(),
        entry_name: String::new(),
        created_at: String::new(),
        changed: Vec::new(),
        state: if disk.waiting {
            EditState::Pending { attempts: 0, last_error: None }
        } else {
            EditState::Pushed
        },
        locked: true,
        damaged: false,
    }
}

/// What the list shows of an edit that cannot be read.
fn damaged(id: &str) -> PendingEdit {
    PendingEdit {
        id: id.to_string(),
        account_id: String::new(),
        entry_id: String::new(),
        entry_name: String::new(),
        created_at: String::new(),
        changed: Vec::new(),
        state: EditState::Pending { attempts: 0, last_error: None },
        locked: false,
        damaged: true,
    }
}

/// Writes an edit sealed with its account's key, then drops the oldest done
/// edits beyond the limit.
pub fn save(ring: &Ring<'_>, edit: &StoredEdit) -> anyhow::Result<()> {
    let dir = dir();
    std::fs::create_dir_all(&dir)?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let disk = Disk {
        id: edit.meta.id.clone(),
        account: keyward_core::paths::account_key(&edit.meta.account_id),
        waiting: edit.meta.is_waiting(),
        sealed: seal(ring, &edit.meta)?,
        next: edit.next.clone(),
        previous: edit.previous.clone(),
    };
    keyward_core::paths::write_private(&path(&edit.meta.id), serde_json::to_string(&disk)?.as_bytes())?;
    prune(ring, &edit.meta.account_id);
    Ok(())
}

/// Keeps at most `KEEP_DONE` done edits of the account, the newest.
fn prune(ring: &Ring<'_>, account_id: &str) {
    let mut done: Vec<(std::path::PathBuf, String)> = files()
        .into_iter()
        .filter_map(|(p, f)| match f {
            OnDisk::Sealed(d) if !d.waiting => match open(ring, account_id, &d) {
                Ok(Some(m)) => Some((p, m.created_at)),
                _ => None,
            },
            _ => None,
        })
        .collect();
    if done.len() <= KEEP_DONE {
        return;
    }
    done.sort_by(|a, b| b.1.cmp(&a.1));
    for (p, _) in done.into_iter().skip(KEEP_DONE) {
        if let Err(e) = std::fs::remove_file(&p) {
            tracing::error!(error = %e, edit = ?p.file_stem(), "an old edit could not be removed");
        }
    }
}

/// One edit of this account, opened.
pub fn load(ring: &Ring<'_>, account_id: &str, id: &str) -> anyhow::Result<StoredEdit> {
    let text = std::fs::read_to_string(path(id)).map_err(|_| keyward_core::fault!("err.editNotFound"))?;
    match parse(&text) {
        Some(OnDisk::Sealed(d)) => {
            let meta = open(ring, account_id, &d)?.ok_or_else(|| keyward_core::fault!("err.editOtherAccount"))?;
            Ok(StoredEdit { meta, next: d.next, previous: d.previous })
        }
        Some(OnDisk::Legacy(l)) if l.meta.account_id == account_id => {
            Ok(StoredEdit { meta: l.meta, next: l.next, previous: l.previous })
        }
        Some(OnDisk::Legacy(_)) => Err(keyward_core::fault!("err.editOtherAccount")),
        Some(OnDisk::Damaged(_)) | None => Err(keyward_core::fault!("err.editDamaged")),
    }
}

pub fn remove(id: &str) -> anyhow::Result<()> {
    std::fs::remove_file(path(id)).map_err(|e| anyhow::anyhow!("the edit cannot be removed: {e}"))
}

/// Every edit, newest first: opened where one of `rings` is its account's,
/// shown as locked where not.
pub fn list(rings: &[(String, Ring<'_>)]) -> Vec<PendingEdit> {
    let mut out: Vec<PendingEdit> = files()
        .into_iter()
        .map(|(_, f)| match f {
            OnDisk::Sealed(d) => {
                let mut shown = None;
                for (id, ring) in rings {
                    match open(ring, id, &d) {
                        Ok(Some(m)) => shown = Some(m),
                        Ok(None) => continue,
                        Err(_) => shown = Some(damaged(&d.id)),
                    }
                    break;
                }
                shown.unwrap_or_else(|| locked(&d))
            }
            OnDisk::Damaged(id) => damaged(&id),
            OnDisk::Legacy(l) => {
                // An old file is shown in full only to its own open vault,
                // like a sealed one.
                if rings.iter().any(|(id, _)| *id == l.meta.account_id) {
                    l.meta
                } else {
                    locked(&Disk {
                        id: l.meta.id.clone(),
                        account: String::new(),
                        waiting: l.meta.is_waiting(),
                        sealed: String::new(),
                        next: Default::default(),
                        previous: Default::default(),
                    })
                }
            }
        })
        .collect();
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    out
}

/// How many edits wait to be sent, over every account, without opening any.
pub fn waiting() -> usize {
    files()
        .into_iter()
        .filter(|(_, f)| match f {
            OnDisk::Sealed(d) => d.waiting,
            OnDisk::Legacy(l) => l.meta.is_waiting(),
            // It may be an edit that never reached the server: it is counted
            // rather than assumed gone.
            OnDisk::Damaged(_) => true,
        })
        .count()
}

/// Every stored edit of one item of this account, newest first — with both of
/// its versions.
pub fn of_entry(ring: &Ring<'_>, account_id: &str, entry_id: &str) -> Vec<StoredEdit> {
    let mut out: Vec<StoredEdit> = files()
        .into_iter()
        .filter_map(|(_, f)| match f {
            OnDisk::Sealed(d) => {
                let meta = open(ring, account_id, &d).ok().flatten()?;
                Some(StoredEdit { meta, next: d.next, previous: d.previous })
            }
            OnDisk::Legacy(l) if l.meta.account_id == account_id => {
                Some(StoredEdit { meta: l.meta, next: l.next, previous: l.previous })
            }
            OnDisk::Legacy(_) | OnDisk::Damaged(_) => None,
        })
        .filter(|s| s.meta.entry_id == entry_id)
        .collect();
    out.sort_by(|a, b| b.meta.created_at.cmp(&a.meta.created_at));
    out
}

/// Rewrites this account's old, unsealed files sealed. Returns how many.
pub fn seal_legacy(ring: &Ring<'_>, account_id: &str) -> usize {
    let mut n = 0;
    for (p, f) in files() {
        let OnDisk::Legacy(l) = f else { continue };
        if l.meta.account_id != account_id {
            continue;
        }
        let edit = StoredEdit { meta: l.meta, next: l.next, previous: l.previous };
        // The old identifier carried the time and the item: a new one is
        // made, and the old file goes.
        let fresh = StoredEdit { meta: PendingEdit { id: keyward_core::edits::edit_id(), ..edit.meta }, ..edit };
        let new_id = fresh.meta.id.clone();
        if let Err(e) = save(ring, &fresh) {
            tracing::error!(error = %e, "an old edit could not be sealed; it stays as it was");
            continue;
        }
        match std::fs::remove_file(&p) {
            Ok(()) => n += 1,
            Err(e) => {
                // Both copies are now there: the sealed one is dropped rather
                // than leaving the edit twice in the queue.
                tracing::error!(error = %e, "the unsealed copy of an edit could not be removed");
                if let Err(e) = remove(&new_id) {
                    tracing::error!(error = %e, edit = %new_id, "and the sealed copy could not be removed either");
                }
            }
        }
    }
    n
}

pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // No calendar dependency: a timestamp is enough for sorting and for
    // showing, and exact calendar arithmetic is not needed here.
    format!("@{secs}")
}

/// Captions of the changed fields, for the list of edits. No values here:
/// they must not reach the queue file even as "before and after".
pub fn changed_fields(labels: &[String]) -> Vec<ChangedField> {
    labels
        .iter()
        .map(|l| ChangedField { label: l.clone(), had_value: true, has_value: true })
        .collect()
}

pub fn pending_state() -> EditState {
    EditState::Pending { attempts: 0, last_error: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(byte: u8) -> rbw::locked::Keys {
        let mut raw = rbw::locked::Vec::new();
        raw.extend(std::iter::repeat_n(byte, 64));
        rbw::locked::Keys::new(raw)
    }

    fn meta(account_id: &str) -> PendingEdit {
        PendingEdit {
            id: "0123abcd".into(),
            account_id: account_id.into(),
            entry_id: "entry-1".into(),
            entry_name: "Secret project VPN".into(),
            created_at: "@1790000000".into(),
            changed: changed_fields(&["field.password".into(), "AUTH CODE".into()]),
            state: pending_state(),
            locked: false,
            damaged: false,
        }
    }

    fn disk(ring: &Ring<'_>, m: &PendingEdit) -> Disk {
        Disk {
            id: m.id.clone(),
            account: keyward_core::paths::account_key(&m.account_id),
            waiting: m.is_waiting(),
            sealed: seal(ring, m).unwrap(),
            next: Default::default(),
            previous: Default::default(),
        }
    }

    #[test]
    fn nothing_about_an_edit_is_in_the_clear() {
        let user = keys(7);
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let m = meta("me@example.com@https://vault.example.com");
        let text = serde_json::to_string(&disk(&ring, &m)).unwrap();
        for leak in ["Secret project", "AUTH CODE", "field.password", "me@example.com", "1790000000"] {
            assert!(!text.contains(leak), "{leak} is on disk in the clear");
        }
        assert!(text.contains(r#""waiting":true"#), "only whether it waits");
    }

    #[test]
    fn an_edit_opens_only_with_its_own_account() {
        let (mine, theirs) = (keys(7), keys(9));
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &mine, orgs: &orgs };
        let other = Ring { user: &theirs, orgs: &orgs };
        let m = meta("me@example.com@https://vault.example.com");
        let d = disk(&ring, &m);

        let opened = open(&ring, &m.account_id, &d).unwrap().expect("its own vault opens it");
        assert_eq!(opened.entry_name, "Secret project VPN");
        assert_eq!(opened.changed[1].label, "AUTH CODE");
        assert!(open(&other, "someone@example.com@https://vault.example.com", &d).unwrap().is_none(), "another account");
        let err = open(&other, &m.account_id, &d).unwrap_err();
        assert!(err.to_string().contains("err.editDamaged"), "its own account and a seal that does not open: damage, loudly");
    }

    #[test]
    fn a_locked_edit_shows_only_that_it_waits() {
        let user = keys(7);
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let shown = locked(&disk(&ring, &meta("a@b@c")));
        assert!(shown.locked && shown.is_waiting());
        assert!(shown.entry_name.is_empty() && shown.changed.is_empty() && shown.account_id.is_empty());
    }

    #[test]
    fn both_shapes_are_read() {
        let user = keys(7);
        let orgs = std::collections::HashMap::new();
        let ring = Ring { user: &user, orgs: &orgs };
        let sealed = serde_json::to_string(&disk(&ring, &meta("a@b@c"))).unwrap();
        assert!(matches!(parse(&sealed), Some(OnDisk::Sealed(_))));
        let legacy = r#"{"id":"1","account_id":"a@b@c","entry_id":"e","entry_name":"n","created_at":"@1",
            "changed":[],"state":{"state":"pushed"},"next":{"id":"e","name":"x"},"previous":{"id":"e","name":"x"}}"#;
        match parse(legacy) {
            Some(OnDisk::Legacy(l)) => assert_eq!(l.meta.entry_name, "n"),
            _ => panic!("the old shape is read"),
        }
        assert!(parse("{ not json").is_none(), "damage is not read as an edit");
    }
}
