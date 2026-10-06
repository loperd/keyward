// Windowed rendering for long lists whose rows have heights known from the
// layout tokens: only the rows in sight (and some either side) are drawn,
// spacers keep the list as tall as it is, so the scrollbar, the scroll
// position and the look stay those of the whole list. The arithmetic is
// pure; the hook only reads the scroller.
import { useCallback, useLayoutEffect, useState, type RefObject } from "react";

/// A list of a few hundred rows draws whole: windowing starts above it.
export const WINDOW_FROM = 150;
/// Rows drawn beyond the edges of the view, either side, in pixels.
export const OVERSCAN_PX = 480;

/// Where each row's box starts and how tall it is, and the whole list's
/// height. A row's top includes the margin above it.
export type RowLayout = { tops: Float64Array; heights: Float64Array; total: number };

/// Rows laid out one under another: `gapAbove` is the margin over a row.
export function layoutOf(n: number, height: (i: number) => number, gapAbove: (i: number) => number): RowLayout {
  const tops = new Float64Array(n);
  const heights = new Float64Array(n);
  let y = 0;
  for (let i = 0; i < n; i++) {
    const h = height(i);
    const g = gapAbove(i);
    if (!(h >= 0) || !(g >= 0)) throw new Error(`row ${i} has no height (${h}) or margin (${g})`);
    y += g;
    tops[i] = y;
    heights[i] = h;
    y += h;
  }
  return { tops, heights, total: y };
}

/// The first row whose bottom is below `y`.
function firstEndingBelow(l: RowLayout, y: number): number {
  let lo = 0;
  let hi = l.tops.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (l.tops[mid]! + l.heights[mid]! <= y) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
/// The first row whose top is at `y` or below it.
function firstStartingFrom(l: RowLayout, y: number): number {
  let lo = 0;
  let hi = l.tops.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (l.tops[mid]! < y) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/// The rows to draw, `[start, end)`, for a view of `height` pixels whose top
/// is `at` pixels into the list; never none while the list has rows.
export function rangeOf(l: RowLayout, at: number, height: number, overscan = OVERSCAN_PX): [number, number] {
  const n = l.tops.length;
  if (!n) return [0, 0];
  const start = Math.min(n - 1, firstEndingBelow(l, Math.max(0, at - overscan)));
  const end = Math.max(start + 1, firstStartingFrom(l, at + height + overscan));
  return [start, end];
}

/// The spacers over and under the drawn rows.
export function spacersOf(l: RowLayout, [start, end]: [number, number]): { above: number; below: number } {
  if (end <= start) return { above: 0, below: l.total };
  const last = end - 1;
  return { above: start > 0 ? l.tops[start]! : 0, below: l.total - (l.tops[last]! + l.heights[last]!) };
}

/// The scroll position that brings a row into view the way
/// `scrollIntoView({ block: "nearest" })` does, or `null` when it is in view.
/// `offset` is where the list starts inside the scroller's content.
export function nearestScroll(l: RowLayout, i: number, offset: number, scrollTop: number, viewH: number): number | null {
  const top = offset + l.tops[i]!;
  const bottom = top + l.heights[i]!;
  if (top < scrollTop) return top;
  if (bottom > scrollTop + viewH) return bottom - viewH;
  return null;
}

/// Where a list starts inside its scroller's content.
export function offsetIn(list: HTMLElement, scroller: HTMLElement): number {
  if (list === scroller) return parseFloat(getComputedStyle(list).paddingTop) || 0;
  return list.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scroller.scrollTop;
}

/// The rows of a list in sight, following its scroller. `scrollerOf` finds
/// the element that scrolls (the list itself, or an ancestor). Off while the
/// list is short: then every row is drawn, as before.
export function useWindow(listRef: RefObject<HTMLElement | null>, scrollerOf: (list: HTMLElement) => HTMLElement, layout: RowLayout, on: boolean): [number, number] {
  const n = layout.tops.length;
  const [range, setRange] = useState<[number, number]>(() => rangeOf(layout, 0, 1000));
  const measure = useCallback(() => {
    const list = listRef.current;
    if (!list) return;
    const sc = scrollerOf(list);
    const at = sc.scrollTop - offsetIn(list, sc);
    const next = rangeOf(layout, at, sc.clientHeight);
    setRange((r) => (r[0] === next[0] && r[1] === next[1] ? r : next));
  }, [listRef, scrollerOf, layout]);
  useLayoutEffect(() => {
    if (!on) return;
    const list = listRef.current;
    if (!list) throw new Error("a windowed list was drawn without its element");
    const sc = scrollerOf(list);
    measure();
    sc.addEventListener("scroll", measure, { passive: true });
    const ro = new ResizeObserver(measure);
    ro.observe(sc);
    return () => {
      sc.removeEventListener("scroll", measure);
      ro.disconnect();
    };
  }, [on, listRef, scrollerOf, measure]);
  // Off, the layout is not built (it may be empty): every row is drawn.
  return on ? [Math.min(range[0], n), Math.min(range[1], n)] : [0, Infinity];
}
