//! Merging copies of one record into one.
//!
//! The window never holds a stored secret, so it cannot tell whether two
//! passwords are the same, nor carry one from a record to another. Both are
//! done here, where the keys are: the comparison says which records hold a
//! field and which of them hold the same value — never the value — and a
//! plan names the fields to take by the record they come from.

use serde::{Deserialize, Serialize};

/// A field of a login that a merge compares and may take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "field", rename_all = "snake_case")]
pub enum MergeSlot {
    Username,
    Password,
    Totp,
    Notes,
    /// A custom field, by its name as the first record that has it spells it.
    Custom { name: String },
    /// The record's passkeys, taken all together.
    Passkeys,
}

/// One record's hold on a slot. Records with the same `group` hold the same
/// value; for passkeys every record is a group of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeHolder {
    pub entry_id: String,
    pub group: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeRow {
    pub slot: MergeSlot,
    /// The value is a secret: the window never shows it, only whether the
    /// records agree.
    pub secret: bool,
    /// The records holding the field, in the order they were asked about.
    pub holders: Vec<MergeHolder>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeComparison {
    pub rows: Vec<MergeRow>,
}

/// A field taken from another record into the kept one. With `as_name` it
/// goes in beside the kept record's own field, as a custom field of that
/// name; without, it takes the field's own place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeTake {
    pub from: String,
    pub slot: MergeSlot,
    #[serde(default)]
    pub as_name: Option<String>,
}

/// The kept record, the records merged into it, and what is taken from them.
/// The addresses of all of them are joined; the others go to the trash once
/// the kept record is saved on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergePlan {
    pub keeper: String,
    pub others: Vec<String>,
    #[serde(default)]
    pub takes: Vec<MergeTake>,
}

impl MergePlan {
    /// A plan that cannot be carried out is refused before anything is
    /// read: no records to merge, the kept one among the others, a record
    /// twice, a field taken from a record that is not merged, one slot
    /// filled twice, or a name for a field beside another that is empty.
    pub fn check(&self) -> Result<(), &'static str> {
        if self.others.is_empty() {
            return Err("err.mergeNothing");
        }
        let mut seen = std::collections::HashSet::new();
        if !std::iter::once(&self.keeper).chain(&self.others).all(|id| seen.insert(id.as_str())) {
            return Err("err.mergeTwice");
        }
        let mut filled = Vec::new();
        let mut named = std::collections::HashSet::new();
        for t in &self.takes {
            if !self.others.contains(&t.from) {
                return Err("err.mergeForeignTake");
            }
            match &t.as_name {
                Some(n) if n.trim().is_empty() => return Err("err.mergeNeedName"),
                Some(n) => {
                    if !named.insert(n.trim().to_lowercase()) {
                        return Err("err.mergeNameTwice");
                    }
                }
                // Passkeys are added, never put in place of others, so they
                // may come from several records.
                None if t.slot == MergeSlot::Passkeys => {}
                None => {
                    if filled.contains(&&t.slot) {
                        return Err("err.mergeSlotTwice");
                    }
                    filled.push(&t.slot);
                }
            }
            if t.as_name.is_some() && t.slot == MergeSlot::Passkeys {
                return Err("err.mergePasskeysNamed");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(takes: Vec<MergeTake>) -> MergePlan {
        MergePlan { keeper: "a".into(), others: vec!["b".into(), "c".into()], takes }
    }
    fn take(from: &str, slot: MergeSlot, as_name: Option<&str>) -> MergeTake {
        MergeTake { from: from.into(), slot, as_name: as_name.map(Into::into) }
    }

    #[test]
    fn a_plan_takes_fields_only_from_the_records_it_merges() {
        assert_eq!(plan(vec![take("b", MergeSlot::Password, None)]).check(), Ok(()));
        assert_eq!(plan(vec![take("a", MergeSlot::Password, None)]).check(), Err("err.mergeForeignTake"));
        assert_eq!(plan(vec![take("z", MergeSlot::Password, None)]).check(), Err("err.mergeForeignTake"));
    }

    #[test]
    fn a_plan_names_each_record_once() {
        let p = MergePlan { keeper: "a".into(), others: vec!["b".into(), "a".into()], takes: vec![] };
        assert_eq!(p.check(), Err("err.mergeTwice"));
        let none = MergePlan { keeper: "a".into(), others: vec![], takes: vec![] };
        assert_eq!(none.check(), Err("err.mergeNothing"));
    }

    #[test]
    fn a_slot_is_filled_once_and_a_field_beside_it_has_a_name_of_its_own() {
        let twice = plan(vec![take("b", MergeSlot::Password, None), take("c", MergeSlot::Password, None)]);
        assert_eq!(twice.check(), Err("err.mergeSlotTwice"));
        let beside = plan(vec![take("b", MergeSlot::Password, None), take("c", MergeSlot::Password, Some("password (c)"))]);
        assert_eq!(beside.check(), Ok(()));
        let same = plan(vec![take("b", MergeSlot::Totp, Some("x")), take("c", MergeSlot::Password, Some("X "))]);
        assert_eq!(same.check(), Err("err.mergeNameTwice"));
        assert_eq!(plan(vec![take("b", MergeSlot::Totp, Some(" "))]).check(), Err("err.mergeNeedName"));
    }

    #[test]
    fn passkeys_come_from_any_number_of_records_and_never_under_a_name() {
        let both = plan(vec![take("b", MergeSlot::Passkeys, None), take("c", MergeSlot::Passkeys, None)]);
        assert_eq!(both.check(), Ok(()));
        assert_eq!(plan(vec![take("b", MergeSlot::Passkeys, Some("keys"))]).check(), Err("err.mergePasskeysNamed"));
    }
}
