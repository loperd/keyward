// Why a thing stands as it does, in words: the long reason a row's mark
// carries in its tooltip and a document's hero says under the title, and the
// one-word form a relation's mark says. Read from the signals and the
// catalogue; nothing is guessed.
import type { Key, Text } from "../i18n";
import { monthsLeft, topSignal, type Signal } from "./signals";
import { type Catalog, type Item, Level, type Member, ItemKind, MemberStatus } from "./types";

/// A plugin's own finding about an item (a key the server refused): it
/// outranks the item's own signals when it is more serious.
export type ExtraSignal = { level: Level; why: Text; short: Text };

/// The live items of each reuse group, in the catalogue's order: built once
/// per list of items (a catalogue is a snapshot, never changed in place), so
/// a vault of thousands asks for partners without a walk over all of them.
const REUSE = new WeakMap<readonly Item[], Map<number, Item[]>>();
export function reuseGroups(items: readonly Item[]): ReadonlyMap<number, readonly Item[]> {
  let g = REUSE.get(items);
  if (!g) {
    g = new Map();
    for (const i of items) {
      if (i.deleted || i.reuseGroup === null) continue;
      const xs = g.get(i.reuseGroup);
      if (xs) xs.push(i);
      else g.set(i.reuseGroup, [i]);
    }
    REUSE.set(items, g);
  }
  return g;
}

/// The items sharing an item's password, itself left out.
export function reusePartners(item: Item, catalog: Catalog): Item[] {
  if (item.reuseGroup === null) return [];
  return (reuseGroups(catalog.items).get(item.reuseGroup) ?? []).filter((i) => i.id !== item.id);
}

/// The part of a name before " — ": "AWS — production" and "AWS — platform
/// billing" are one service. A name without the dash names no service.
export function serviceOf(name: string): string | null {
  const m = /^(.+?)\s+[—–-]\s+/.exec(name);
  return m ? m[1]!.trim().toLowerCase() : null;
}
/// The live items of each service, in the catalogue's order, built once per
/// list of items.
const SERVICES = new WeakMap<readonly Item[], Map<string, Item[]>>();
export function serviceGroups(items: readonly Item[]): ReadonlyMap<string, readonly Item[]> {
  let g = SERVICES.get(items);
  if (!g) {
    g = new Map();
    for (const i of items) {
      if (i.deleted) continue;
      const s = serviceOf(i.name);
      if (!s) continue;
      const xs = g.get(s);
      if (xs) xs.push(i);
      else g.set(s, [i]);
    }
    SERVICES.set(items, g);
  }
  return g;
}
export function sameService(item: Item, catalog: Catalog): Item[] {
  const s = serviceOf(item.name);
  if (!s) return [];
  return (serviceGroups(catalog.items).get(s) ?? []).filter((i) => i.id !== item.id && !(i.reuseGroup !== null && i.reuseGroup === item.reuseGroup));
}

/// The level and the long reason of an item.
export function itemState(item: Item, catalog: Catalog, now: Date, extra?: ExtraSignal): { level: Level; why: Text; short: Text } {
  return itemStateOf(topSignal(item, now), item, catalog, extra);
}
/// The same from the item's most serious signal, already read.
export function itemStateOf(s: Signal, item: Item, catalog: Catalog, extra?: ExtraSignal): { level: Level; why: Text; short: Text } {
  const own = { level: s.level, why: whyOf(s, item, catalog), short: shortOf(s) };
  if (extra && rank(extra.level) < rank(own.level)) return extra;
  return own;
}

const RANK: Record<Level, number> = { [Level.Critical]: 0, [Level.Action]: 1, [Level.Warning]: 2, [Level.Healthy]: 3, [Level.Unknown]: 4 };
const rank = (l: Level) => RANK[l];

function whyOf(s: Signal, item: Item, catalog: Catalog): Text {
  switch (s.key) {
    case "sig.reused": {
      const ps = reusePartners(item, catalog);
      return ps.length === 1 ? { key: "why.reusedWith", args: { name: ps[0]!.name } } : { key: "why.reused", args: { n: ps.length } };
    }
    case "sig.expired":
      return { key: "why.expired" };
    case "sig.expiresSoon":
      return { key: "why.expiresSoon", args: { n: s.args?.n ?? 0 } };
    case "sig.oldPassword":
      return { key: "why.oldPassword", args: { n: s.args?.n ?? 0 } };
    case "sig.totp":
    case "sig.passkey":
      return { key: "why.none" };
    case "sig.reprompt":
      return { key: "why.reprompt" };
    case "sig.passwordOnly":
      return { key: "why.passwordOnly" };
    case "sig.none":
      return { key: item.kind === ItemKind.SecureNote ? "why.noteUnchecked" : "why.nothing" };
  }
}

function shortOf(s: Signal): Text {
  const k: Record<Signal["key"], Key> = {
    "sig.reused": "short.reused",
    "sig.expired": "short.expired",
    "sig.expiresSoon": "short.expiring",
    "sig.oldPassword": "short.oldPassword",
    "sig.totp": "level.healthy",
    "sig.passkey": "level.healthy",
    "sig.reprompt": "level.healthy",
    "sig.passwordOnly": "level.unknown",
    "sig.none": "level.unknown",
  };
  return { key: k[s.key] };
}

/// A member's level and why.
export function memberState(m: Member): { level: Level; why: Text } {
  if (m.status === MemberStatus.Invited) return { level: Level.Unknown, why: { key: "why.invited" } };
  if (m.status === MemberStatus.Accepted) return { level: Level.Action, why: { key: "why.accepted" } };
  if (m.twoFactor === false) return { level: Level.Warning, why: { key: "why.noTwoFactor" } };
  return { level: Level.Healthy, why: { key: "why.twoFactorOn" } };
}

/// A card's expiry as people write it: `12 / 2026`.
export function expiryText(expires: string): string {
  monthsLeft(expires, new Date());
  return `${expires.slice(5)} / ${expires.slice(0, 4)}`;
}
