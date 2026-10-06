// The core's hot paths over vaults the size of real ones: 1k, 10k and 20k
// items, dozens of folders, four organisations, the first with 300 members.
// Run with `npx vitest bench --run`.
import { bench, describe } from "vitest";
import { DEMO_NOW } from "../demo";
import { setLang, Lang } from "../i18n";
import { Directory } from "../path/directory";
import { DEFAULT_PLACES } from "../path/places";
import { Query, columns, crumbs, rows, type Verb, ColumnType, TokenKey } from "../path/query";
import { suggest } from "../path/suggest";
import { EMPTY } from "../path/query";
import { accessModel } from "../map/model";
import { orient, placeVertical, laneWidths } from "../map/layout";
import { CORE_VERBS } from "../verbs/core";
import { synthetic } from "./synthetic";

setLang(Lang.En);
const verbs: Verb[] = CORE_VERBS;
const SIZES = [1_000, 10_000, 20_000];
const TOKENS = { top: 72, bottom: 32, gap: 56, maxStep: 136 };

for (const n of SIZES) {
  const catalog = synthetic({ items: n, seed: 7 });
  const build = () => new Directory(catalog, [], { now: DEMO_NOW, places: DEFAULT_PLACES });
  const dir = build();
  const q = new Query(dir, verbs);
  const org = dir.node("org:so0");
  const deep = q.compile(`${org.slug} › ${dir.node("org:so0/collections").slug} › ${dir.node("collection:sc0-0").slug}`);
  const typed = `${org.slug} state:attention gi`;

  describe(`${n} items`, () => {
    bench("Directory build", () => {
      build();
    });
    bench("cold: build + rows(all) + results(state:attention)", () => {
      const d = build();
      const qq = new Query(d, verbs);
      rows(qq, { type: ColumnType.Kids, parent: "all", at: 0, sel: null });
      qq.results("root", { tokens: [{ k: TokenKey.State, v: "attention" }], words: [] });
    });
    bench("compile + serialize (deep path)", () => {
      q.serialize(q.compile(q.serialize(deep)));
    });
    bench("typing frame: compile + columns + rows", () => {
      const st = q.compile(typed);
      for (const c of columns(q, st.segs, st.map)) rows(q, c);
    });
    // Every keystroke a new word: the results are never the ones kept.
    let k = 0;
    bench("typing frame, a new word each time (results not kept)", () => {
      const st = q.compile(`${org.slug} state:attention w${k++ % 1000}`);
      for (const c of columns(q, st.segs, st.map)) rows(q, c);
    });
    let k2 = 0;
    bench("typing frame at root, a new word each time", () => {
      const st = q.compile(`w${k2++ % 1000}`);
      for (const c of columns(q, st.segs, st.map)) rows(q, c);
    });
    bench("rows of the biggest column (all)", () => {
      rows(q, { type: ColumnType.Kids, parent: "all", at: 0, sel: null });
    });
    bench("results of state:attention at root", () => {
      q.results("root", { tokens: [{ k: TokenKey.State, v: "attention" }], words: [] });
    });
    bench("suggestions for a 2-letter prefix", () => {
      suggest(q, EMPTY, "gi", DEFAULT_PLACES);
    });
    bench("crumbs (deep path)", () => {
      crumbs(q, deep);
    });
    bench("access map model + layout (300 members)", () => {
      const md = accessModel(dir, "org:so0");
      orient(md);
      laneWidths(md, new Map(md.nodes.map((x) => [x.id, 120])), md.lanes.map(() => 80));
      placeVertical(md, 1200, TOKENS);
    });
  });
}
