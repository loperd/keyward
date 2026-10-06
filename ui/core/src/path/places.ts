// Places: saved queries. A place is a line with a name and a picture — an
// icon, or the mark of the one state it asks for. The window comes with a few;
// the ones a person saves are kept by the app. A place's name and line are
// vault data (an item's name, the words searched for), so they are never kept
// in the clear: by default they live in memory and go with the session, and
// only a store the app hands in explicitly (the stand's demo) keeps them.
// Storage may be blocked (a private window): a place then lives for the
// session. Stored data that does not parse is reported, never half used, and
// a report never quotes what was stored.
import type { Text } from "../i18n";
import { Level, parseLevel } from "../model/types";
import { isEnumValue } from "../model/enum";
import { isFilter, STATES, type PathState, type Query, TokenKey } from "./query";

export type Place = { id: string; name: Text; line: string; icon?: string; level?: Level; mine?: boolean };

export const DEFAULT_PLACES: Place[] = [
  { id: "attention", name: { key: "place.attention" }, line: "state:attention", icon: "pulse" },
  { id: "critical", name: { key: "place.critical" }, line: "state:critical", level: Level.Critical },
  { id: "cards", name: { key: "place.cards" }, line: "kind:card", icon: "card" },
];

/// Where the app keeps a person's places; `localStorage` has this shape.
export type PlaceStore = { getItem(k: string): string | null; setItem(k: string, v: string): void };
export const PLACE_KEY = "keyward.places";

/// A store that lives in memory only, dropped with `clear` when the session
/// closes: the default until places can be kept inside the vault.
export function memoryPlaceStore(): PlaceStore & { clear(): void } {
  const m = new Map<string, string>();
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => void m.set(k, v), clear: () => m.clear() };
}

/// boundary: a person's saved places, with what could not be read. A store that
/// refuses to be read is a problem of its own, not an empty list.
export function loadPlaces(store: PlaceStore, icons: ReadonlySet<string>): { places: Place[]; problems: string[] } {
  let rawText: string | null;
  try {
    rawText = store.getItem(PLACE_KEY);
  } catch (e) {
    return { places: [], problems: [`saved places are unavailable: storage is blocked (${String(e)})`] };
  }
  if (rawText === null) return { places: [], problems: [] };
  let xs: unknown;
  try {
    xs = JSON.parse(rawText);
  } catch {
    // The parser's message quotes the text; the report must not.
    return { places: [], problems: ["saved places are corrupted and were not loaded: not JSON"] };
  }
  if (!Array.isArray(xs)) return { places: [], problems: ["saved places are corrupted and were not loaded: not a list"] };
  const places: Place[] = [];
  const problems: string[] = [];
  for (const [n, x] of (xs as unknown[]).entries()) {
    const o = x as Record<string, unknown> | null;
    const ok =
      o !== null &&
      typeof o === "object" &&
      typeof o.name === "string" &&
      o.name !== "" &&
      typeof o.line === "string" &&
      o.line !== "" &&
      (o.level !== undefined ? isEnumValue(Level, o.level) : typeof o.icon === "string" && icons.has(o.icon));
    if (!ok) {
      problems.push(`saved place #${n + 1} is malformed and was skipped`);
      continue;
    }
    places.push({
      id: `mine:${o.line as string}`,
      name: { raw: o.name as string },
      line: o.line as string,
      ...(o.level !== undefined ? { level: parseLevel(o.level) } : { icon: o.icon as string }),
      mine: true,
    });
  }
  return { places, problems };
}

/// Keeps a person's places; `false` when the store refused, so the window can
/// say the place lives for this session only.
export function storePlaces(store: PlaceStore, places: Place[]): boolean {
  const mine = places
    .filter((p) => p.mine)
    .map((p) => {
      if (!("raw" in p.name)) throw new Error(`a saved place has a dictionary name: ${p.id}`);
      return { name: p.name.raw, line: p.line, ...(p.level ? { level: p.level } : { icon: p.icon }) };
    });
  try {
    store.setItem(PLACE_KEY, JSON.stringify(mine));
    return true;
  } catch {
    return false;
  }
}

/// The steps of a state without its map or verb, as a key to compare.
const pathKey = (q: Query, st: PathState) => q.serialize({ segs: st.segs, map: null, verb: null, arg: "" });

/// The place the path stands on, if it is one.
export function currentPlace(q: Query, st: PathState, places: Place[]): Place | null {
  if (!st.segs.length) return null;
  const here = pathKey(q, st);
  return places.find((p) => pathKey(q, q.compile(p.line)) === here) ?? null;
}

/// "Save as a place": the path as it stands, named the way its last crumb
/// reads, with that crumb's picture.
export function placeFor(q: Query, st: PathState): Place {
  const l = st.segs[st.segs.length - 1];
  if (!l) throw new Error("the root is not a place to save");
  const line = pathKey(q, st);
  if (!isFilter(l)) {
    const n = q.dir.node(l.id);
    return { id: `mine:${line}`, name: { raw: q.nodeLabel(l.id) }, line, icon: n.icon, mine: true };
  }
  const prev = st.segs[st.segs.length - 2];
  const name = (prev && !isFilter(prev) ? `${q.nodeLabel(prev.id)} · ` : "") + q.filterName(l.filter);
  const f = l.filter;
  const lone = f.tokens.length === 1 && f.words.length === 0 && f.tokens[0]!.k === TokenKey.State ? STATES[f.tokens[0]!.v] : undefined;
  const level = lone ? (lone.length === 1 ? lone[0]! : Level.Action) : undefined;
  return { id: `mine:${line}`, name: { raw: name }, line, ...(level ? { level } : { icon: f.tokens.length ? "filter" : "search" }), mine: true };
}
