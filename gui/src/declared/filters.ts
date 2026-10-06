// Filtering and sorting a declared table, in the window: free text, or
// `facet:value` words in the same box, or the facet selects — all three one
// filter underneath. The plugin gives each row its facet values and sort
// keys; nothing here goes back to it.
import type { Facet, TableRow } from "./types";

export type Filters = Record<string, string | undefined>;
export type Sort = { key: string; desc: boolean };

/// The values of a facet, with how many rows carry each.
export function valuesOf(rows: TableRow[], facet: string): { value: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const r of rows) {
    const v = r.facets?.[facet];
    if (v !== undefined) counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  return [...counts.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => a.value.localeCompare(b.value));
}

/// The search box read: `id:value` words for a facet of the table, the rest
/// free text.
export function parseQuery(q: string, facets: Facet[]): { text: string[]; filters: Filters } {
  const ids = new Set(facets.map((f) => f.id));
  const text: string[] = [];
  const filters: Filters = {};
  for (const word of q.trim().split(/\s+/).filter(Boolean)) {
    const at = word.indexOf(":");
    const id = at > 0 ? word.slice(0, at).toLowerCase() : "";
    if (ids.has(id)) {
      const value = word.slice(at + 1).replace(/^[<>]/, "");
      if (value) filters[id] = value;
    } else {
      text.push(word.toLowerCase());
    }
  }
  return { text, filters };
}

/// The rows the query and the selects let through. `textOf` is what a row
/// is searched by.
export function applyFilters(rows: TableRow[], facets: Facet[], query: string, selects: Filters, textOf: (r: TableRow) => string): TableRow[] {
  const { text, filters } = parseQuery(query, facets);
  const all: Filters = { ...filters, ...selects };
  return rows.filter((r) => {
    for (const [facet, want] of Object.entries(all)) {
      if (!want) continue;
      const got = r.facets?.[facet];
      if (got === undefined || got.toLowerCase() !== want.toLowerCase()) return false;
    }
    if (text.length === 0) return true;
    const hay = textOf(r).toLowerCase();
    return text.every((w) => hay.includes(w));
  });
}

export function sortRows(rows: TableRow[], sort: Sort, valueOf: (r: TableRow, key: string) => string | number): TableRow[] {
  const out = [...rows];
  out.sort((a, b) => {
    const x = a.sort?.[sort.key] ?? valueOf(a, sort.key);
    const y = b.sort?.[sort.key] ?? valueOf(b, sort.key);
    const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
    return sort.desc ? -c : c;
  });
  return out;
}
