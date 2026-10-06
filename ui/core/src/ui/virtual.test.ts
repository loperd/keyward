// Windowed lists: the arithmetic that keeps a long list as tall as it is and
// draws only what is in sight.
import { describe, expect, it } from "vitest";
import { layoutOf, nearestScroll, rangeOf, spacersOf } from "./virtual";

// Rows of 48 with a caption of 32 every 10, and a breath of 16 over each
// caption after the first.
const N = 1000;
const L = layoutOf(
  N,
  (i) => (i % 10 === 0 ? 32 : 48),
  (i) => (i > 0 && i % 10 === 0 ? 16 : 0),
);

describe("a windowed list", () => {
  it("lays rows out one under another, margins included", () => {
    expect(L.tops[0]).toBe(0);
    expect(L.tops[1]).toBe(32);
    expect(L.tops[10]).toBe(32 + 9 * 48 + 16);
    expect(L.total).toBe(100 * 32 + 900 * 48 + 99 * 16);
    expect(() => layoutOf(2, () => NaN, () => 0)).toThrow();
  });
  it("draws every row in sight and a margin either side, and spacers for the rest", () => {
    for (const at of [0, 1, 500, 12_345, L.total - 600, L.total]) {
      const [s, e] = rangeOf(L, at, 600, 200);
      expect(e).toBeGreaterThan(s);
      // Every row that meets [at - 200, at + 800] is drawn.
      for (let i = 0; i < N; i++) {
        const top = L.tops[i]!;
        const bottom = top + L.heights[i]!;
        if (bottom > Math.max(0, at - 200) && top < at + 800) expect(i >= s && i < e, `row ${i} at ${at}`).toBe(true);
      }
      const sp = spacersOf(L, [s, e]);
      let drawn = 0;
      for (let i = s; i < e; i++) drawn += L.heights[i]! + (i > s ? L.tops[i]! - (L.tops[i - 1]! + L.heights[i - 1]!) : 0);
      // The spacers and the drawn rows are the whole list: nothing jumps.
      expect(sp.above + drawn + sp.below).toBeCloseTo(L.total, 6);
    }
  });
  it("draws nothing of an empty list", () => {
    const empty = layoutOf(0, () => 0, () => 0);
    expect(rangeOf(empty, 0, 600)).toEqual([0, 0]);
  });
  it("scrolls a row into view the nearest way, and not at all when it is in view", () => {
    expect(nearestScroll(L, 1, 16, 0, 600)).toBeNull();
    // Below the view: its bottom meets the view's bottom.
    const i = 200;
    expect(nearestScroll(L, i, 16, 0, 600)).toBe(16 + L.tops[i]! + L.heights[i]! - 600);
    // Above the view: its top meets the view's top.
    expect(nearestScroll(L, 5, 16, 50_000, 600)).toBe(16 + L.tops[5]!);
  });
});
