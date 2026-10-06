// Rows that change under a person's eyes say so: a row that comes (a
// restore, a new item, a change taken back) or changes (a rename, a saved
// edit) lights up for a moment; a row that goes (a trash) folds away instead
// of vanishing. Only rows of a list that stays on the screen move: a new list
// is a new sheet, and comes in as one.
import { useCallback, useLayoutEffect, useRef, useState } from "react";
import { currentLang } from "../i18n";

/// A list as it was drawn: each row's id at its place, and what it showed.
export type Snapshot<T> = { order: readonly (string | null)[]; sigs: ReadonlyMap<string, string>; items: readonly T[]; lang: string };

export function snapshotOf<T>(items: readonly T[], idOf: (x: T) => string | null, sigOf: (x: T) => string, lang: string = currentLang()): Snapshot<T> {
  const order = items.map(idOf);
  const sigs = new Map<string, string>();
  items.forEach((x, i) => {
    const id = order[i];
    if (id === null || id === undefined) return;
    if (sigs.has(id)) throw new Error(`the row "${id}" stands twice in one list`);
    sigs.set(id, sigOf(x));
  });
  return { order, sigs, items, lang };
}

/// What moved between two drawings of one list: the rows that came or
/// changed, and the rows that went, with the place each stood at.
export function diffRows<T>(before: Snapshot<T>, after: Snapshot<T>): { fresh: string[]; gone: { id: string; at: number; item: T }[] } {
  const fresh: string[] = [];
  for (const [id, sig] of after.sigs) {
    const was = before.sigs.get(id);
    if (was === undefined || was !== sig) fresh.push(id);
  }
  const gone: { id: string; at: number; item: T }[] = [];
  before.order.forEach((id, at) => {
    if (id !== null && id !== undefined && !after.sigs.has(id)) gone.push({ id, at, item: before.items[at]! });
  });
  return { fresh, gone };
}

export type RowMotion<T> = {
  /// Whether the row lights up now.
  fresh: (id: string) => boolean;
  /// The rows folding away, at the places they stood.
  gone: readonly { id: string; at: number; item: T }[];
  /// A row's motion played out: it stops being lit, or a gone row leaves.
  settle: (id: string) => void;
};

/// The motion of one list's rows. `enabled` off (a long, windowed list)
/// keeps every row still; the first drawing is still too.
export function useRowMotion<T>(items: readonly T[], idOf: (x: T) => string | null, sigOf: (x: T) => string, enabled: boolean): RowMotion<T> {
  const prev = useRef<Snapshot<T> | null>(null);
  const [fresh, setFresh] = useState<ReadonlySet<string>>(() => new Set());
  // Words read anew in another language are no change of the rows.
  const lang = currentLang();
  const [gone, setGone] = useState<readonly { id: string; at: number; item: T }[]>([]);
  // Read before paint: a row that went is drawn folding in the same frame
  // it would have vanished in.
  useLayoutEffect(() => {
    if (!enabled) {
      prev.current = null;
      return;
    }
    const now = snapshotOf(items, idOf, sigOf, lang);
    const before = prev.current;
    prev.current = now;
    if (!before || before.lang !== lang) return;
    const d = diffRows(before, now);
    if (d.fresh.length) setFresh((s) => new Set([...s, ...d.fresh]));
    setGone((g) => {
      // A row that came back stops folding.
      const kept = g.filter((x) => !now.sigs.has(x.id));
      const added = d.gone.filter((x) => !kept.some((k) => k.id === x.id));
      return kept.length === g.length && !added.length ? g : [...kept, ...added];
    });
    // `idOf` and `sigOf` read the same graph as `items`: a new list is the
    // only change that matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, enabled, lang]);
  const settle = useCallback((id: string) => {
    setFresh((s) => {
      if (!s.has(id)) return s;
      const next = new Set(s);
      next.delete(id);
      return next;
    });
    setGone((g) => (g.some((x) => x.id === id) ? g.filter((x) => x.id !== id) : g));
  }, []);
  return { fresh: (id) => fresh.has(id), gone, settle };
}

/// The rows to draw: the list's own, with the rows folding away put back
/// at their places.
export function withGone<T>(items: readonly T[], gone: readonly { at: number; item: T }[]): { item: T; gone: boolean }[] {
  const out = items.map((item) => ({ item, gone: false }));
  for (const g of [...gone].sort((a, b) => a.at - b.at)) out.splice(Math.min(g.at, out.length), 0, { item: g.item, gone: true });
  return out;
}
