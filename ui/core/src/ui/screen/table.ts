// Filtering and sorting a declared table, in the window: the facets' choices
// and the free words of the table's search. The plugin gives each row its
// facet values and sort keys; nothing here goes back to it. Pure.
import type { ScreenTableRow } from "../../plugin/screen";

export type Filters = Readonly<Record<string, string | undefined>>;
export type Sort = { key: string; desc: boolean };

/// The values of a facet, with how many rows carry each.
export function valuesOf(rows: readonly ScreenTableRow[], facet: string): { value: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const r of rows) {
    const v = r.facets[facet];
    if (v !== undefined) counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  return [...counts.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => a.value.localeCompare(b.value));
}

/// The rows the chosen facets and the words let through. `textOf` is what a
/// row is searched by.
export function applyFilters(rows: readonly ScreenTableRow[], query: string, selects: Filters, textOf: (r: ScreenTableRow) => string): ScreenTableRow[] {
  const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  return rows.filter((r) => {
    for (const [facet, want] of Object.entries(selects)) {
      if (want === undefined) continue;
      if (r.facets[facet] !== want) return false;
    }
    if (!words.length) return true;
    const hay = textOf(r).toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}

export function sortRows(rows: readonly ScreenTableRow[], sort: Sort, valueOf: (r: ScreenTableRow, key: string) => string | number): ScreenTableRow[] {
  const out = [...rows];
  out.sort((a, b) => {
    const x = a.sort[sort.key] ?? valueOf(a, sort.key);
    const y = b.sort[sort.key] ?? valueOf(b, sort.key);
    const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
    return sort.desc ? -c : c;
  });
  return out;
}

/// A line of the "what changes" view.
export enum DiffKind {
  Same = "same",
  Add = "add",
  Del = "del",
}
export type DiffLine = { kind: DiffKind; text: string };

/// A line diff: the longest common subsequence, which for manifests of a few
/// hundred lines is instant.
export function diffLines(before: string, after: string): DiffLine[] {
  const a = before.split("\n");
  const b = after.split("\n");
  const n = a.length;
  const m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: DiffKind.Same, text: a[i]! });
      i++;
      j++;
    } else if (lcs[i + 1]![j]! >= lcs[i]![j + 1]!) out.push({ kind: DiffKind.Del, text: a[i++]! });
    else out.push({ kind: DiffKind.Add, text: b[j++]! });
  }
  while (i < n) out.push({ kind: DiffKind.Del, text: a[i++]! });
  while (j < m) out.push({ kind: DiffKind.Add, text: b[j++]! });
  return out;
}

/// The server fills in what nobody wrote (status, uid, timestamps): leaving
/// those lines out keeps a diff about what a person changed.
export function withoutNoise(yaml: string): string {
  const out: string[] = [];
  let skip = -1;
  for (const line of yaml.split("\n")) {
    const indent = line.length - line.trimStart().length;
    if (skip >= 0 && (indent > skip || line.trim() === "")) continue;
    skip = -1;
    const key = line.trim().split(":")[0];
    if ((indent === 0 && key === "status") || (indent === 2 && ["uid", "resourceVersion", "generation", "creationTimestamp"].includes(key ?? ""))) {
      skip = indent;
      continue;
    }
    out.push(line);
  }
  return out.join("\n");
}

/// "5 minutes ago", in the language of the moment, from seconds since the
/// epoch.
export function agoSeconds(at: number, lang: string, now = Date.now()): string {
  const diff = Math.round(at - now / 1000);
  const fmt = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
  const abs = Math.abs(diff);
  if (abs < 60) return fmt.format(diff, "second");
  if (abs < 3600) return fmt.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return fmt.format(Math.round(diff / 3600), "hour");
  return fmt.format(Math.round(diff / 86400), "day");
}
