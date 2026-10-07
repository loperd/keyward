// Why a thing stands as it does, in words: the long reason a row's mark
// carries in its tooltip and a document's hero says under the title, and the
// one-word form a relation's mark says. Read from the signals and the
// catalogue; nothing is guessed.
import type { Key, Text } from "../i18n";
import { siteHost } from "./fields";
import { monthsLeft, signals, type Signal } from "./signals";
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

const norm = (s: string | null) => (s ?? "").trim().toLowerCase();

/// A host's own name, without its zone: "icloud" of "appleid.icloud.com",
/// "bbc" of "www.bbc.co.uk".
export function brandOf(host: string): string | null {
  const labels = host.toLowerCase().replace(/:\d+$/, "").split(".").filter(Boolean);
  if (labels.length < 2 || labels.every((l) => /^\d+$/.test(l))) return null;
  const n = labels.length;
  // A country's second level ("co.uk", "com.au") is part of the zone.
  const zone2 = n >= 3 && labels[n - 1]!.length === 2 && labels[n - 2]!.length <= 3;
  return labels[zone2 ? n - 3 : n - 2]!;
}
const HOSTLIKE = /^[^\s/]+\.[a-z]{2,}$/i;
const WORD = /[\p{L}\p{N}]{3,}/gu;
/// What tells which service an item is for: the brands of its addresses
/// (and of its name, when the name is an address), and the words of its
/// name.
type Marks = { brands: Set<string>; words: Set<string> };
const MARKS = new WeakMap<Item, Marks>();
function marksOf(item: Item): Marks {
  let m = MARKS.get(item);
  if (!m) {
    const brands = new Set<string>();
    for (const u of item.uris) {
      const h = siteHost(u);
      const b = h && brandOf(h);
      if (b) brands.add(b);
    }
    const name = item.name.trim();
    if (HOSTLIKE.test(name)) {
      const b = brandOf(name);
      if (b) brands.add(b);
    }
    const words = new Set([...name.toLowerCase().matchAll(WORD)].map((x) => x[0]));
    m = { brands, words };
    MARKS.set(item, m);
  }
  return m;
}
const meets = (a: Marks, b: Marks) => [...a.brands].some((x) => b.brands.has(x) || b.words.has(x));
/// Two items for one service: the same name, or a brand of one in the
/// other's addresses or name ("second icloud" and "appleid.icloud.com").
export function sameSite(a: Item, b: Item): boolean {
  if (norm(a.name) === norm(b.name)) return true;
  const ma = marksOf(a);
  const mb = marksOf(b);
  return meets(ma, mb) || meets(mb, ma);
}

/// The same record twice — one kind, one service, one login: an import done
/// twice, a copy left behind, or an old one with the password before the
/// last change. Without a login the password must be the same too. Not a
/// password reused across services, so not a critical one.
export function isDuplicate(a: Item, b: Item): boolean {
  if (a.id === b.id || a.kind !== b.kind || a.kind !== ItemKind.Login || a.deleted || b.deleted) return false;
  if (norm(a.subtitle) !== norm(b.subtitle)) return false;
  if (!norm(a.subtitle) && (a.reuseGroup === null || a.reuseGroup !== b.reuseGroup)) return false;
  return sameSite(a, b);
}

/// The live logins of each login name, built once per list of items.
const BY_LOGIN = new WeakMap<readonly Item[], Map<string, Item[]>>();
function byLogin(items: readonly Item[]): ReadonlyMap<string, readonly Item[]> {
  let g = BY_LOGIN.get(items);
  if (!g) {
    g = new Map();
    for (const i of items) {
      if (i.deleted || i.kind !== ItemKind.Login) continue;
      const k = norm(i.subtitle);
      const xs = g.get(k);
      if (xs) xs.push(i);
      else g.set(k, [i]);
    }
    BY_LOGIN.set(items, g);
  }
  return g;
}
/// The other copies of an item's record, in the catalogue's order.
export const duplicatesOf = (item: Item, catalog: Catalog): Item[] =>
  item.kind !== ItemKind.Login || item.deleted ? [] : (byLogin(catalog.items).get(norm(item.subtitle)) ?? []).filter((p) => isDuplicate(item, p));
/// The partners that are really other records sharing the password.
export const reusedWith = (item: Item, catalog: Catalog): Item[] => reusePartners(item, catalog).filter((p) => !isDuplicate(item, p));

/// Where an item lives, as a person reads it: the organisation and its
/// collection, or the folder, or the personal vault.
export function placeOf(item: Item, catalog: Catalog): Text {
  if (item.orgId) {
    const org = catalog.orgs.find((o) => o.id === item.orgId)?.name;
    const coll = item.collectionIds.map((c) => catalog.collections.find((x) => x.id === c)?.name).filter((x): x is string => !!x)[0];
    if (!org) throw new Error(`item ${item.id} belongs to an organisation the catalogue does not hold`);
    return { raw: coll ? `${org} › ${coll}` : org };
  }
  if (item.folderId) {
    const f = catalog.folders.find((x) => x.id === item.folderId);
    if (!f) throw new Error(`item ${item.id} is in a folder the catalogue does not hold`);
    return { raw: f.name };
  }
  return { key: "personal" };
}
/// Another item named for a person: with its place when the name alone would
/// not tell it from this one.
export function partnerName(p: Item, item: Item, catalog: Catalog): Text {
  return norm(p.name) === norm(item.name) ? { key: "why.namedAt", args: { name: p.name, place: placeOf(p, catalog) } } : { raw: p.name };
}

/// An item's signals with what only the catalogue can tell: a copy of the
/// same record is a duplicate, and a password shared only with copies is not
/// a reuse.
export function settledSignals(item: Item, catalog: Catalog, now: Date): Signal[] {
  const sigs = signals(item, now);
  const dups = duplicatesOf(item, catalog).length;
  if (dups === 0) return sigs;
  const out = sigs.filter((s) => s.key !== "sig.reused");
  out.push({ level: Level.Warning, key: "sig.duplicate", args: { n: dups } });
  if (sigs.some((s) => s.key === "sig.reused")) {
    const others = reusedWith(item, catalog).length;
    if (others > 0) out.push({ level: Level.Critical, key: "sig.reused", args: { n: others } });
  }
  return out.sort((a, b) => rank(a.level) - rank(b.level));
}

/// The level and the long reason of an item.
export function itemState(item: Item, catalog: Catalog, now: Date, extra?: ExtraSignal): { level: Level; why: Text; short: Text } {
  return itemStateOf(settledSignals(item, catalog, now)[0]!, item, catalog, extra);
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
      const ps = reusedWith(item, catalog);
      return ps.length === 1 ? { key: "why.reusedWith", args: { name: partnerName(ps[0]!, item, catalog) } } : { key: "why.reused", args: { n: ps.length } };
    }
    case "sig.duplicate": {
      const ds = duplicatesOf(item, catalog);
      return ds.length === 1 ? { key: "why.duplicate", args: { place: placeOf(ds[0]!, catalog) } } : { key: "why.duplicates", args: { n: ds.length } };
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
    "sig.duplicate": "short.duplicate",
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
