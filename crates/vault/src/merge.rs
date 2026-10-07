//! Merging copies of one login, here where the keys are: the window learns
//! which records agree on a field, never what the field holds, and a field
//! taken from another record is read and sealed again without leaving the
//! daemon.

use keyward_bw::model::Cipher;
use keyward_core::edits::{CustomEdit, ItemEdit};
use keyward_core::merge::{MergeComparison, MergeHolder, MergePlan, MergeRow, MergeSlot};
use zeroize::Zeroizing;

use crate::read::Ring;

/// A login's type in Bitwarden's terms.
const LOGIN: u8 = 1;
const HIDDEN: u8 = 1;
const LINKED: u8 = 3;
/// The one field of a stored passkey left in the clear.
const PASSKEY_PLAIN: &[&str] = &["creationDate"];

/// What one record holds in one slot, as compared: a value, or a link to
/// another of its fields.
#[derive(PartialEq, Eq)]
enum Held {
    Value(Zeroizing<String>),
    Linked(Option<u32>),
}

/// A custom field read out of a record.
struct Custom {
    name: String,
    kind: u8,
    linked_id: Option<u32>,
    held: Held,
}

fn only_logins(ciphers: &[&Cipher]) -> anyhow::Result<()> {
    if ciphers.iter().any(|c| c.kind != LOGIN || c.login.is_none()) {
        return Err(keyward_core::fault!("err.mergeOnlyLogins"));
    }
    Ok(())
}

/// A value the record holds, read; a value it holds and cannot read is a
/// refusal, not an absence — a merge must not take it for an empty field.
fn read(ring: &Ring<'_>, c: &Cipher, raw: Option<&str>) -> anyhow::Result<Option<Zeroizing<String>>> {
    match raw {
        None => Ok(None),
        Some(v) => {
            let plain = crate::read::decrypt_for(ring, c, v).ok_or_else(|| keyward_core::fault!("err.undecryptable"))?;
            Ok((!plain.is_empty()).then(|| Zeroizing::new(plain)))
        }
    }
}

fn builtin(ring: &Ring<'_>, c: &Cipher, slot: &MergeSlot) -> anyhow::Result<Option<Zeroizing<String>>> {
    let login = c.login.as_ref();
    match slot {
        MergeSlot::Username => read(ring, c, login.and_then(|l| l.username.as_deref())),
        MergeSlot::Password => read(ring, c, login.and_then(|l| l.password.as_deref())),
        MergeSlot::Totp => read(ring, c, login.and_then(|l| l.totp.as_deref())),
        MergeSlot::Notes => read(ring, c, c.notes.as_deref()),
        MergeSlot::Custom { .. } | MergeSlot::Passkeys => unreachable!("not a built-in field"),
    }
}

fn customs(ring: &Ring<'_>, c: &Cipher) -> anyhow::Result<Vec<Custom>> {
    c.fields
        .iter()
        .map(|f| {
            let name = read(ring, c, f.name.as_deref())?.ok_or_else(|| keyward_core::fault!("err.mergeUnnamedField"))?;
            let held = if f.kind == LINKED {
                Held::Linked(f.linked_id)
            } else {
                Held::Value(read(ring, c, f.value.as_deref())?.unwrap_or_default())
            };
            Ok(Custom { name: name.trim().to_string(), kind: f.kind, linked_id: f.linked_id, held })
        })
        .collect()
}

fn passkeys(c: &Cipher) -> &[serde_json::Value] {
    match c.login.as_ref().and_then(|l| l.fido2_credentials.as_ref()) {
        Some(serde_json::Value::Array(list)) => list,
        _ => &[],
    }
}

/// Numbers the values: records holding the same one get the same group.
fn grouped(held: Vec<(&str, Held)>) -> Vec<MergeHolder> {
    let mut seen: Vec<&Held> = Vec::new();
    let mut out = Vec::with_capacity(held.len());
    for (id, h) in &held {
        let group = match seen.iter().position(|s| *s == h) {
            Some(g) => g,
            None => {
                seen.push(h);
                seen.len() - 1
            }
        };
        out.push(MergeHolder { entry_id: (*id).to_string(), group: group as u32 });
    }
    out
}

/// Which records hold each field and which of them agree, in the order of
/// `ciphers`.
pub(crate) fn compare(ring: &Ring<'_>, ciphers: &[&Cipher]) -> anyhow::Result<MergeComparison> {
    only_logins(ciphers)?;
    let mut rows = Vec::new();
    for (slot, secret) in [(MergeSlot::Username, false), (MergeSlot::Password, true), (MergeSlot::Totp, true), (MergeSlot::Notes, true)] {
        let mut held = Vec::new();
        for c in ciphers {
            if let Some(v) = builtin(ring, c, &slot)? {
                held.push((c.id.as_str(), Held::Value(v)));
            }
        }
        if !held.is_empty() {
            rows.push(MergeRow { slot, secret, holders: grouped(held) });
        }
    }

    // Custom fields meet by name, whatever its case; the first record's
    // spelling names the row.
    let read: Vec<(&str, Vec<Custom>)> = ciphers.iter().map(|c| Ok((c.id.as_str(), customs(ring, c)?))).collect::<anyhow::Result<_>>()?;
    let mut names: Vec<String> = Vec::new();
    for (_, fields) in &read {
        for f in fields {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(&f.name)) {
                names.push(f.name.clone());
            }
        }
    }
    for name in names {
        let mut held = Vec::new();
        let mut secret = false;
        for (id, fields) in &read {
            let mut same = fields.iter().filter(|f| f.name.eq_ignore_ascii_case(&name));
            let Some(f) = same.next() else { continue };
            if same.next().is_some() {
                return Err(keyward_core::fault!("err.mergeFieldNamedTwice", "name" => name));
            }
            secret |= f.kind == HIDDEN;
            let h = match &f.held {
                Held::Value(v) => Held::Value(v.clone()),
                Held::Linked(l) => Held::Linked(*l),
            };
            held.push((*id, h));
        }
        rows.push(MergeRow { slot: MergeSlot::Custom { name }, secret, holders: grouped(held) });
    }

    let with_keys: Vec<MergeHolder> = ciphers
        .iter()
        .filter(|c| !passkeys(c).is_empty())
        .enumerate()
        .map(|(i, c)| MergeHolder { entry_id: c.id.clone(), group: i as u32 })
        .collect();
    if !with_keys.is_empty() {
        rows.push(MergeRow { slot: MergeSlot::Passkeys, secret: false, holders: with_keys });
    }
    Ok(MergeComparison { rows })
}

/// A passkey of `from`, sealed again for `into`: every field but the
/// creation date is a string encrypted with the record's key.
fn resealed(ring: &Ring<'_>, from: &Cipher, into: &Cipher, passkey: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let serde_json::Value::Object(fields) = passkey else {
        return Err(keyward_core::fault!("err.passkeyDamaged"));
    };
    let mut out = serde_json::Map::new();
    for (k, v) in fields {
        let moved = match v {
            serde_json::Value::String(sealed) if !PASSKEY_PLAIN.contains(&k.as_str()) => {
                let plain = Zeroizing::new(crate::read::decrypt_for(ring, from, sealed).ok_or_else(|| keyward_core::fault!("err.passkeyDamaged"))?);
                serde_json::Value::String(crate::read::encrypt_for(ring, into, &plain)?)
            }
            other => other.clone(),
        };
        out.insert(k.clone(), moved);
    }
    Ok(serde_json::Value::Object(out))
}

/// The edit that makes `keeper` the merged record: the plan's fields, read
/// out of the records they come from, and every record's addresses.
pub(crate) fn edit_for(ring: &Ring<'_>, keeper: &Cipher, others: &[&Cipher], plan: &MergePlan) -> anyhow::Result<ItemEdit> {
    plan.check().map_err(|code| keyward_core::fault!(code))?;
    let all: Vec<&Cipher> = std::iter::once(keeper).chain(others.iter().copied()).collect();
    only_logins(&all)?;
    let mut edit = ItemEdit::default();

    let uris_of = |c: &Cipher| -> anyhow::Result<Vec<String>> {
        let login = c.login.as_ref().expect("a login, checked above");
        let mut out = Vec::new();
        for u in login.uris.iter().filter_map(|u| u.uri.as_deref()) {
            if let Some(v) = read(ring, c, Some(u))? {
                out.push(v.trim().to_string());
            }
        }
        Ok(out)
    };
    let own = uris_of(keeper)?;
    let mut joined = own.clone();
    for c in others {
        for u in uris_of(c)? {
            if !joined.iter().any(|x| x.eq_ignore_ascii_case(&u)) {
                joined.push(u);
            }
        }
    }
    if joined != own {
        edit.uris = Some(joined);
    }

    let keeper_fields = customs(ring, keeper)?;
    for take in &plan.takes {
        let from = *others.iter().find(|c| c.id == take.from).expect("a take from a merged record, checked by the plan");
        let gone = || keyward_core::fault!("err.mergeFieldGone");
        // The value taken, how a custom field holds it, and its link.
        let (value, kind, linked_id): (Zeroizing<String>, u8, Option<u32>) = match &take.slot {
            MergeSlot::Passkeys => {
                let list = passkeys(from);
                if list.is_empty() {
                    return Err(gone());
                }
                for p in list {
                    edit.add_passkeys.push(resealed(ring, from, keeper, p)?);
                }
                continue;
            }
            MergeSlot::Custom { name } => {
                let fields = customs(ring, from)?;
                let f = fields.into_iter().find(|f| f.name.eq_ignore_ascii_case(name)).ok_or_else(gone)?;
                let value = match f.held {
                    Held::Value(v) => v,
                    Held::Linked(_) => Zeroizing::new(String::new()),
                };
                (value, f.kind, f.linked_id)
            }
            slot => {
                let v = builtin(ring, from, slot)?.ok_or_else(gone)?;
                let kind = if *slot == MergeSlot::Username { 0 } else { HIDDEN };
                (v, kind, None)
            }
        };
        let secret: keyward_core::proto::Secret = Zeroizing::new(value.to_string());
        match (&take.as_name, &take.slot) {
            (Some(name), _) => {
                let name = name.trim().to_string();
                if keeper_fields.iter().any(|f| f.name.eq_ignore_ascii_case(&name)) {
                    return Err(keyward_core::fault!("err.mergeNameTaken", "name" => name));
                }
                edit.custom.push(CustomEdit { name, value: secret, kind, linked_id });
            }
            (None, MergeSlot::Username) => edit.username = Some(value.to_string()),
            (None, MergeSlot::Password) => edit.password = Some(secret),
            (None, MergeSlot::Totp) => edit.totp = Some(secret),
            (None, MergeSlot::Notes) => edit.notes = Some(secret),
            (None, MergeSlot::Custom { name }) => {
                // In the kept record's own spelling when it has the field.
                let name = keeper_fields.iter().find(|f| f.name.eq_ignore_ascii_case(name)).map_or_else(|| name.clone(), |f| f.name.clone());
                edit.custom.push(CustomEdit { name, value: secret, kind, linked_id });
            }
            (None, MergeSlot::Passkeys) => unreachable!("passkeys were added above"),
        }
    }
    Ok(edit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyward_bw::model::{Field, Login, Uri};
    use keyward_core::merge::MergeTake;
    use std::collections::HashMap;

    fn keys() -> rbw::locked::Keys {
        let mut raw = rbw::locked::Vec::new();
        raw.extend(std::iter::repeat_n(7u8, 64));
        rbw::locked::Keys::new(raw)
    }

    struct Rec<'a> {
        id: &'a str,
        username: Option<&'a str>,
        password: Option<&'a str>,
        totp: Option<&'a str>,
        uris: &'a [&'a str],
        fields: &'a [(&'a str, u8, &'a str)],
        passkeys: usize,
    }
    const REC: Rec<'static> = Rec { id: "", username: None, password: None, totp: None, uris: &[], fields: &[], passkeys: 0 };

    fn cipher(ring: &Ring<'_>, r: Rec<'_>) -> Cipher {
        let blank = Cipher::default();
        let seal = |v: &str| crate::read::encrypt_for(ring, &blank, v).unwrap();
        let passkeys = (0..r.passkeys)
            .map(|i| serde_json::json!({ "credentialId": seal(&format!("{}-{i}", r.id)), "rpId": seal("icloud.com"), "creationDate": "2026-01-01T00:00:00.000Z" }))
            .collect::<Vec<_>>();
        Cipher {
            id: r.id.into(),
            kind: LOGIN,
            name: seal(r.id),
            login: Some(Login {
                username: r.username.map(seal),
                password: r.password.map(seal),
                totp: r.totp.map(seal),
                uris: r.uris.iter().map(|u| Uri { uri: Some(seal(u)), match_type: None }).collect(),
                fido2_credentials: (!passkeys.is_empty()).then_some(serde_json::Value::Array(passkeys)),
                ..Default::default()
            }),
            fields: r.fields.iter().map(|(n, k, v)| Field { kind: *k, name: Some(seal(n)), value: Some(seal(v)), linked_id: None }).collect(),
            ..Default::default()
        }
    }

    fn row<'a>(c: &'a MergeComparison, slot: &MergeSlot) -> Vec<(&'a str, u32)> {
        c.rows.iter().find(|r| &r.slot == slot).map(|r| r.holders.iter().map(|h| (h.entry_id.as_str(), h.group)).collect()).unwrap_or_default()
    }

    #[test]
    fn the_comparison_says_who_agrees_and_never_what() {
        let k = keys();
        let orgs = HashMap::new();
        let ring = Ring { user: &k, orgs: &orgs };
        let a = cipher(&ring, Rec { id: "second", username: Some("me@icloud.com"), password: Some("hunter2"), fields: &[("PIN", 1, "1234")], ..REC });
        let b = cipher(&ring, Rec { id: "appleid", username: Some("me@icloud.com"), password: Some("hunter2"), totp: Some("JBSWY3DPEHPK3PXP"), fields: &[("pin", 1, "9999"), ("Recovery", 0, "x")], passkeys: 1, ..REC });
        let c = compare(&ring, &[&a, &b]).unwrap();

        assert_eq!(row(&c, &MergeSlot::Username), vec![("second", 0), ("appleid", 0)]);
        assert_eq!(row(&c, &MergeSlot::Password), vec![("second", 0), ("appleid", 0)]);
        assert_eq!(row(&c, &MergeSlot::Totp), vec![("appleid", 0)]);
        assert_eq!(row(&c, &MergeSlot::Custom { name: "PIN".into() }), vec![("second", 0), ("appleid", 1)], "one name whatever its case, two values");
        assert_eq!(row(&c, &MergeSlot::Passkeys), vec![("appleid", 0)]);
        let wire = serde_json::to_string(&c).unwrap();
        for leak in ["hunter2", "1234", "9999", "JBSWY3DPEHPK3PXP", "me@icloud.com"] {
            assert!(!wire.contains(leak), "{leak} left the daemon");
        }
    }

    #[test]
    fn the_kept_record_takes_what_it_lacks_replaces_what_it_was_told_and_keeps_both_under_a_new_name() {
        let k = keys();
        let orgs = HashMap::new();
        let ring = Ring { user: &k, orgs: &orgs };
        let keeper = cipher(&ring, Rec { id: "second", username: Some("me@icloud.com"), password: Some("old"), uris: &["icloud.com"], fields: &[("PIN", 1, "1234")], ..REC });
        let other = cipher(&ring, Rec { id: "appleid", username: Some("me@icloud.com"), password: Some("new"), totp: Some("JBSWY3DPEHPK3PXP"), uris: &["ICLOUD.com", "appleid.apple.com"], fields: &[("pin", 1, "9999")], passkeys: 2, ..REC });
        let take = |slot, as_name: Option<&str>| MergeTake { from: "appleid".into(), slot, as_name: as_name.map(Into::into) };
        let plan = MergePlan {
            keeper: "second".into(),
            others: vec!["appleid".into()],
            takes: vec![take(MergeSlot::Totp, None), take(MergeSlot::Password, None), take(MergeSlot::Custom { name: "PIN".into() }, Some("PIN (appleid)")), take(MergeSlot::Passkeys, None)],
        };
        let edit = edit_for(&ring, &keeper, &[&other], &plan).unwrap();

        assert_eq!(edit.uris.as_deref(), Some(&["icloud.com".to_string(), "appleid.apple.com".to_string()][..]), "addresses joined once each");
        assert_eq!(edit.totp.as_deref().map(String::as_str), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(edit.password.as_deref().map(String::as_str), Some("new"));
        assert!(edit.username.is_none(), "the kept record's own login stays");
        assert_eq!(edit.custom.len(), 1);
        assert_eq!((edit.custom[0].name.as_str(), edit.custom[0].kind, edit.custom[0].value.as_str()), ("PIN (appleid)", 1, "9999"));
        assert_eq!(edit.add_passkeys.len(), 2);
        let id = edit.add_passkeys[0]["credentialId"].as_str().unwrap();
        assert_eq!(crate::read::decrypt_for(&ring, &keeper, id).as_deref(), Some("appleid-0"), "sealed for the kept record");
        assert_eq!(edit.add_passkeys[0]["creationDate"], "2026-01-01T00:00:00.000Z");
    }

    #[test]
    fn a_name_already_in_the_kept_record_is_refused_not_overwritten() {
        let k = keys();
        let orgs = HashMap::new();
        let ring = Ring { user: &k, orgs: &orgs };
        let keeper = cipher(&ring, Rec { id: "a", password: Some("1"), fields: &[("pin", 1, "1")], ..REC });
        let other = cipher(&ring, Rec { id: "b", password: Some("2"), ..REC });
        let plan = MergePlan { keeper: "a".into(), others: vec!["b".into()], takes: vec![MergeTake { from: "b".into(), slot: MergeSlot::Password, as_name: Some("PIN".into()) }] };
        let err = edit_for(&ring, &keeper, &[&other], &plan).unwrap_err();
        assert!(err.to_string().starts_with("err.mergeNameTaken"));
    }

    #[test]
    fn a_field_the_other_record_does_not_hold_is_refused() {
        let k = keys();
        let orgs = HashMap::new();
        let ring = Ring { user: &k, orgs: &orgs };
        let keeper = cipher(&ring, Rec { id: "a", password: Some("1"), ..REC });
        let other = cipher(&ring, Rec { id: "b", password: Some("2"), ..REC });
        let plan = MergePlan { keeper: "a".into(), others: vec!["b".into()], takes: vec![MergeTake { from: "b".into(), slot: MergeSlot::Totp, as_name: None }] };
        assert_eq!(edit_for(&ring, &keeper, &[&other], &plan).unwrap_err().to_string(), "err.mergeFieldGone");
    }

    #[test]
    fn only_logins_are_merged() {
        let k = keys();
        let orgs = HashMap::new();
        let ring = Ring { user: &k, orgs: &orgs };
        let a = cipher(&ring, Rec { id: "a", ..REC });
        let mut note = cipher(&ring, Rec { id: "b", ..REC });
        note.kind = 2;
        note.login = None;
        assert_eq!(compare(&ring, &[&a, &note]).unwrap_err().to_string(), "err.mergeOnlyLogins");
    }
}
