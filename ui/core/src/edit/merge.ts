// A merge as a person decides it: one record kept, its name and its own
// fields standing, and for every value another record holds that it does
// not — take it into its place, keep it beside under a name of its own, or
// let it go with the copy. What the kept record lacks is taken by default;
// what it holds differently is kept as it is until a person says otherwise.
// Pure: the comparison comes from where the keys are, and the plan goes back
// there; no value is ever here.
import type { Key, Text } from "../i18n";
import type { Catalog, Item } from "../model/types";
import { duplicatesOf } from "../model/reasons";
import { MergeField, type MergeComparison, type MergePlan, type MergeRow, type MergeSlot, type MergeTake } from "../writes";

/// What becomes of one value another record holds.
export enum MergeChoice {
  /// It goes to the trash with its record.
  Drop = "drop",
  /// It takes the field's place in the kept record: added where the kept
  /// record has none, put in place of its own where it has one.
  Fill = "fill",
  /// It is kept beside the kept record's own, as a custom field named anew.
  Beside = "beside",
}

/// A row's state, as the merge sheet shows it.
export enum RowState {
  /// Every record that holds the field holds the same value.
  Same = "same",
  /// The kept record lacks it and another has it.
  Missing = "missing",
  /// The records disagree.
  Differs = "differs",
}

/// One value of a row that the kept record does not hold: a group of the
/// comparison, by the first other record that holds it.
export type MergeOffer = { group: number; from: string; holders: string[]; choice: MergeChoice; name: string };
export type MergeLine = { key: string; slot: MergeSlot; secret: boolean; state: RowState; keeperHolds: boolean; offers: MergeOffer[] };
export type MergeDraft = { keeper: string; others: string[]; lines: MergeLine[] };

/// A slot's key: what a row and its decisions are found by.
export const slotKey = (s: MergeSlot): string => (s.field === MergeField.Custom ? `custom:${s.name.toLowerCase()}` : s.field);
/// A slot's caption for the name of a field kept beside another.
export const slotLabel = (s: MergeSlot): Text => (s.field === MergeField.Custom ? { raw: s.name } : { key: `merge.slot.${s.field}` });

/// The record and the copies a merge is offered for: the item first, then
/// its copies, and the copies' own copies, in the catalogue's order.
export function mergeGroup(item: Item, catalog: Catalog): Item[] {
  const out = [item];
  for (let i = 0; i < out.length; i++)
    for (const d of duplicatesOf(out[i]!, catalog)) if (!out.some((x) => x.id === d.id)) out.push(d);
  return out;
}

/// The default name of a value kept beside the kept record's own: the
/// field's caption and the record it came from, made unique.
function besideName(label: string, fromName: string, taken: Set<string>): string {
  const base = `${label} (${fromName})`;
  let name = base;
  for (let n = 2; taken.has(name.toLowerCase()); n++) name = `${base} ${n}`;
  return name;
}

/// The sheet's first state for a kept record: everything it lacks is taken
/// from the first record that has it, everything it holds stays.
export function draftMerge(cmp: MergeComparison, keeper: string, group: Item[], label: (s: MergeSlot) => string): MergeDraft {
  const others = group.map((i) => i.id).filter((id) => id !== keeper);
  if (!group.some((i) => i.id === keeper)) throw new Error(`the kept record ${keeper} is not one of the merged`);
  const nameOf = (id: string) => group.find((i) => i.id === id)!.name;
  const taken = new Set(cmp.rows.filter((r) => r.slot.field === MergeField.Custom && r.holders.some((h) => h.itemId === keeper)).map((r) => (r.slot as { name: string }).name.toLowerCase()));
  const lines = cmp.rows.map((r) => lineOf(r, keeper, others, nameOf, label, taken));
  return { keeper, others, lines };
}

function lineOf(r: MergeRow, keeper: string, others: string[], nameOf: (id: string) => string, label: (s: MergeSlot) => string, taken: Set<string>): MergeLine {
  const mine = r.holders.find((h) => h.itemId === keeper);
  const passkeys = r.slot.field === MergeField.Passkeys;
  const groups = new Map<number, string[]>();
  for (const h of r.holders) {
    if (h.itemId === keeper || !others.includes(h.itemId)) continue;
    if (!passkeys && mine && h.group === mine.group) continue;
    groups.set(h.group, [...(groups.get(h.group) ?? []), h.itemId]);
  }
  let filled = !!mine && !passkeys;
  const offers = [...groups].map(([group, holders]): MergeOffer => {
    // Passkeys are all added; a field the kept record lacks is taken from
    // the first that has it.
    const choice = passkeys || !filled ? MergeChoice.Fill : MergeChoice.Drop;
    if (choice === MergeChoice.Fill && !passkeys) filled = true;
    const name = passkeys ? "" : besideName(label(r.slot), nameOf(holders[0]!), taken);
    if (name) taken.add(name.toLowerCase());
    return { group, from: holders[0]!, holders, choice, name };
  });
  const state = offers.length === 0 ? RowState.Same : !mine || passkeys ? RowState.Missing : RowState.Differs;
  return { key: slotKey(r.slot), slot: r.slot, secret: r.secret, state, keeperHolds: !!mine, offers };
}

/// A choice made on one offer: one value only fills a field, so filling it
/// with one lets another that filled it go. Passkeys are all added.
export function choose(d: MergeDraft, key: string, group: number, choice: MergeChoice): MergeDraft {
  return {
    ...d,
    lines: d.lines.map((l) => {
      if (l.key !== key) return l;
      const one = l.slot.field !== MergeField.Passkeys && choice === MergeChoice.Fill;
      return { ...l, offers: l.offers.map((o) => (o.group === group ? { ...o, choice } : one && o.choice === MergeChoice.Fill ? { ...o, choice: MergeChoice.Drop } : o)) };
    }),
  };
}
export function rename(d: MergeDraft, key: string, group: number, name: string): MergeDraft {
  return { ...d, lines: d.lines.map((l) => (l.key !== key ? l : { ...l, offers: l.offers.map((o) => (o.group === group ? { ...o, name } : o)) })) };
}

/// Why the merge cannot run yet, as a dictionary key with its values, or
/// `null`: the same rules the backend holds it to, said before ↵.
export function mergeProblem(d: MergeDraft, cmp: MergeComparison): Text | null {
  if (d.others.length === 0) return { key: "err.mergeNothing" };
  const own = new Set(cmp.rows.filter((r) => r.slot.field === MergeField.Custom && r.holders.some((h) => h.itemId === d.keeper)).map((r) => (r.slot as { name: string }).name.trim().toLowerCase()));
  const seen = new Set<string>();
  for (const l of d.lines)
    for (const o of l.offers) {
      if (o.choice !== MergeChoice.Beside) continue;
      const n = o.name.trim();
      if (!n) return { key: "err.mergeNeedName" };
      if (own.has(n.toLowerCase())) return { key: "err.mergeNameTaken", args: { name: n } };
      if (seen.has(n.toLowerCase())) return { key: "err.mergeNameTwice" };
      seen.add(n.toLowerCase());
    }
  return null;
}

/// The plan the backend carries out.
export function planOf(d: MergeDraft): MergePlan {
  const takes: MergeTake[] = [];
  for (const l of d.lines)
    for (const o of l.offers) {
      if (o.choice === MergeChoice.Drop) continue;
      takes.push({ from: o.from, slot: l.slot, asName: o.choice === MergeChoice.Beside ? o.name.trim() : null });
    }
  return { keeper: d.keeper, others: d.others, takes };
}

/// A plan that cannot be carried out, refused before anything is read: the
/// rules the daemon holds a plan to (`keyward_core::merge::MergePlan::check`),
/// for a backend that merges in the tab.
export function planRefusal(p: MergePlan): Extract<Key, `err.${string}`> | null {
  if (p.others.length === 0) return "err.mergeNothing";
  const ids = [p.keeper, ...p.others];
  if (new Set(ids).size !== ids.length) return "err.mergeTwice";
  const filled = new Set<string>();
  const named = new Set<string>();
  for (const t of p.takes) {
    if (!p.others.includes(t.from)) return "err.mergeForeignTake";
    if (t.asName !== null) {
      if (!t.asName.trim()) return "err.mergeNeedName";
      if (named.has(t.asName.trim().toLowerCase())) return "err.mergeNameTwice";
      named.add(t.asName.trim().toLowerCase());
    } else if (t.slot.field !== MergeField.Passkeys) {
      if (filled.has(slotKey(t.slot))) return "err.mergeSlotTwice";
      filled.add(slotKey(t.slot));
    }
    if (t.asName !== null && t.slot.field === MergeField.Passkeys) return "err.mergePasskeysNamed";
  }
  return null;
}
