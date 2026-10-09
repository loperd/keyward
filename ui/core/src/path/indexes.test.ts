// The indexes the graph and the query keep, each checked against the plain
// walk it replaces, over a synthetic vault of a few thousand items.
import { describe, expect, it, beforeEach } from "vitest";
import { DEMO, DEMO_NOW } from "../demo";
import { demoContributions } from "../demo-backend";
import { setLang, text, textsOf, Lang } from "../i18n";
import { Directory, EMPTY_FOLDERS, isStep, slugify, type Node, NodeKind, MapKind } from "./directory";
import { Query, rows, type Filter, TokenKey, ColumnType } from "./query";
import { suggest } from "./suggest";
import { EMPTY } from "./query";
import { reuseGroups, reusePartners } from "../model/reasons";
import { orgFindings } from "../model/findings";
import { accessModel, mapModel, onMap } from "../map/model";
import { pathsThrough, orient, placeVertical, spread } from "../map/layout";
import type { MapModel } from "../map/types";
import { synthetic } from "../bench/synthetic";
import { CORE_VERBS } from "../verbs/core";
import type { Catalog } from "../model/types";

const catalog = synthetic({ items: 3000, seed: 11, members: 80, collectionsPerOrg: 10, folders: 12, base: DEMO });
const dir = () => new Directory(catalog, demoContributions(), { now: DEMO_NOW });

beforeEach(() => setLang(Lang.Ru));

describe("the synthetic vault", () => {
  it("is the same for the same seed and differs for another", () => {
    expect(synthetic({ items: 500, seed: 5 })).toEqual(synthetic({ items: 500, seed: 5 }));
    expect(synthetic({ items: 500, seed: 5 })).not.toEqual(synthetic({ items: 500, seed: 6 }));
  });
  it("has what a real vault has: folders, organisations, members, reuse, expiries, a trash", () => {
    const c = synthetic({ items: 2000, seed: 1 });
    expect(c.items).toHaveLength(2000);
    expect(c.folders.length).toBe(40);
    expect(c.members.filter((m) => m.orgId === c.orgs[0]!.id)).toHaveLength(300);
    expect(c.items.some((i) => i.reuseGroup !== null)).toBe(true);
    expect(c.items.some((i) => i.expires)).toBe(true);
    expect(c.items.some((i) => i.deleted)).toBe(true);
    expect(() => new Directory(c, [], { now: DEMO_NOW })).not.toThrow();
  });
  it("refuses a count that is not a whole number", () => {
    expect(() => synthetic({ items: -1 })).toThrow();
    expect(() => synthetic({ items: 1.5 })).toThrow();
  });
});

describe("slugs", () => {
  /// The rule as it is written for every script.
  const reference = (s: string) =>
    s
      .toLowerCase()
      .normalize("NFKC")
      .replace(/[^\p{L}\p{N}]+/gu, "-")
      .replace(/^-+|-+$/g, "");
  it("read plain ASCII the same way the rule for every script does", () => {
    const samples = ["GitLab — platform", "  AWS -- prod  ", "a", "", "---", "Wi-Fi 5G", "x_y.z/w", "ABC123def", "\t\n", "id_ed25519 — production", "Дом", "Ｆｕｌｌ", "Ünïcode name"];
    let seed = 1;
    const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
    for (let i = 0; i < 2000; i++) samples.push(Array.from({ length: Math.floor(rnd() * 20) }, () => String.fromCharCode(Math.floor(rnd() * 128))).join(""));
    for (const s of samples) expect(slugify(s), JSON.stringify(s)).toBe(reference(s));
  });
  it("number a name taken many times on, without a gap, around slugs taken otherwise", () => {
    const items = Array.from({ length: 30 }, (_, i) => ({ ...DEMO.items[0]!, id: `dup${i}`, name: "GitHub", reuseGroup: null, reused: 0 }));
    // "github-3" is a name of its own, taken before the numbering reaches it.
    items.splice(1, 0, { ...DEMO.items[0]!, id: "own3", name: "GitHub 3", reuseGroup: null, reused: 0 });
    const d = new Directory({ ...DEMO, items }, [], { now: DEMO_NOW });
    const slugs = items.map((i) => d.node(`item:${i.id}`).slug);
    expect(slugs.slice(0, 4)).toEqual(["github", "github-3", "github-2", "github-4"]);
    expect(new Set(slugs).size).toBe(slugs.length);
  });
});

describe("the graph's indexes", () => {
  it("keep each node's kids, the same each time and frozen", () => {
    const d = dir();
    for (const n of d.all()) {
      if (!n.kids) continue;
      const k = d.kids(n.id);
      expect(k).toEqual(n.kids());
      expect(d.kids(n.id)).toBe(k);
      expect(Object.isFrozen(k)).toBe(true);
      expect(d.kidIds(n.id)).toEqual(n.kids().filter(isStep).map((e) => e.id));
    }
    expect(() => (d.kids("root") as unknown as unknown[]).push({ gap: true })).toThrow();
  });
  it("keep the universe of a scope, as the walk finds it", () => {
    const d = dir();
    const walk = (scope: string): string[] => {
      if (scope === "root") return d.all().filter((n) => n.result).map((n) => n.id);
      const out = new Set<string>();
      const seen = new Set<string>();
      const go = (id: string) => {
        for (const k of d.kidIds(id)) {
          if (seen.has(k)) continue;
          seen.add(k);
          const n = d.node(k);
          if (n.result) out.add(k);
          if (n.kind !== NodeKind.Member) go(k);
        }
      };
      go(scope);
      return [...out];
    };
    for (const n of d.all().filter((x) => x.kind !== NodeKind.Item)) {
      expect(d.universe(n.id)).toEqual(walk(n.id));
      expect(d.universe(n.id)).toBe(d.universe(n.id));
    }
  });
  it("list the nodes, and the nodes of a kind, in the order they were added", () => {
    const d = dir();
    expect(d.list()).toEqual(d.all());
    for (const k of [NodeKind.Org, NodeKind.Member, NodeKind.Item, NodeKind.Folder, NodeKind.Collection, NodeKind.Section, NodeKind.Plugin] as Node["kind"][]) expect(d.ofKind(k)).toEqual(d.all().filter((n) => n.kind === k));
  });
  it("read a node's words in every language once", () => {
    const d = dir();
    for (const n of d.all()) expect(d.searchTexts(n.id)).toEqual(textsOf(n.name));
  });
  it("keep a member's reach as the catalogue says it", () => {
    const d = dir();
    for (const m of catalog.members)
      expect(d.reach(m)).toEqual(catalog.collections.filter((c) => c.orgId === m.orgId).map((c) => ({ collection: c.id, perm: m.accessAll ? "manage" : (m.access[c.id] ?? null) })));
  });
  it("count every item of an organisation's collections once, even listed twice", () => {
    const twice: Catalog = { ...DEMO, items: DEMO.items.map((i) => (i.id === "travel" ? { ...i, collectionIds: ["finance", "finance", "platform"] } : i)) };
    const d = new Directory(twice, [], { now: DEMO_NOW });
    expect(d.kidIds("collection:finance").filter((x) => x === "item:travel")).toHaveLength(1);
    expect(d.kidIds("collection:platform")).toContain("item:travel");
  });
});

describe("reuse groups", () => {
  it("name the same partners as a walk over every item", () => {
    for (const it of catalog.items) {
      const walk = it.reuseGroup === null ? [] : catalog.items.filter((i) => !i.deleted && i.id !== it.id && i.reuseGroup === it.reuseGroup);
      expect(reusePartners(it, catalog)).toEqual(walk);
    }
    expect(reuseGroups(catalog.items)).toBe(reuseGroups(catalog.items));
  });
});

describe("the query's indexes", () => {
  const q = () => new Query(dir(), CORE_VERBS);
  const filters: Filter[] = [
    { tokens: [{ k: TokenKey.State, v: "attention" }], words: [] },
    { tokens: [{ k: TokenKey.State, v: "critical" }], words: ["gi"] },
    { tokens: [{ k: TokenKey.Kind, v: "card" }], words: [] },
    { tokens: [{ k: TokenKey.Host, v: "*.prod.*" }], words: [] },
    { tokens: [], words: ["aws", "prod"] },
  ];
  it("keep a filter's results as the plain walk finds them", () => {
    const query = q();
    const ranks = { critical: 0, action: 1, warning: 2, healthy: 3, unknown: 4 };
    for (const scope of ["root", "org:so0", "personal", "all"])
      for (const f of filters) {
        const plain = query.dir
          .universe(scope)
          .filter((id) => query.matches(id, f))
          .sort((a, b) => ranks[query.dir.node(a).level] - ranks[query.dir.node(b).level]);
        expect(query.results(scope, f)).toEqual(plain);
        // The same filter written anew is the same kept list.
        expect(query.results(scope, { tokens: f.tokens.map((x) => ({ ...x })), words: [...f.words] })).toBe(query.results(scope, f));
      }
  });
  it("group a results column as a walk per group does", () => {
    const query = q();
    for (const f of filters) {
      const ids = query.results("root", f);
      const plain = (["items", "hosts", "members", "clusters"] as const).flatMap((g) => {
        const xs = ids.filter((id) => query.dir.node(id).result?.group === g);
        return xs.length ? [{ heading: { key: `group.${g}` }, count: xs.length }, ...xs.map((id) => ({ id }))] : [];
      });
      expect(rows(query, { type: ColumnType.Results, scope: "root", filter: f, at: 0, sel: null })).toEqual(plain);
    }
  });
  it("know a list's members and its words", () => {
    const query = q();
    const list = query.dir.kidIds("all");
    for (const id of [list[0]!, list[list.length - 1]!, "item:nope", "root"]) expect(query.inList(list, id)).toBe(list.includes(id));
    // A word steps to the first of the next list with that slug or name.
    const first = query.dir.node(list[5]!);
    expect(query.compile(`all ${first.slug}`).segs.at(-1)).toEqual({ id: first.id });
    setLang(Lang.En);
    expect(query.compile("acme members").segs.at(-1)).toEqual({ id: "org:acme/members" });
    setLang(Lang.Ru);
    expect(query.compile("acme участники").segs.at(-1)).toEqual({ id: "org:acme/members" });
  });
  it("offer the same places elsewhere as a walk over every node", () => {
    const query = q();
    for (const frag of ["gi", "aw", "pl", "уч", "zz"]) {
      const out = suggest(query, EMPTY, frag, []).filter((o) => "key" in o.group && o.group.key === "suggest.elsewhere");
      const next = new Set(query.listAfter([]));
      const plain = query.dir
        .all()
        .filter((x) => x.id !== "root" && !next.has(x.id) && (x.slug.includes(frag) || textsOf(x.name).some((w) => w.includes(frag))))
        .slice(0, 4);
      expect(out.map((o) => text(o.label))).toEqual(plain.map((n) => text(n.name)));
    }
  });
});

describe("maps and findings over a large organisation", () => {
  it("know their points", () => {
    const d = dir();
    const m = { kind: MapKind.Access, anchor: "org:so0" };
    const md = mapModel(d, m);
    for (const id of ["member:sm0-0", "collection:sc0-0", "item:s1", "item:nope", "root"]) expect(onMap(d, m, id)).toBe(md.nodes.some((n) => n.id === id));
  });
  it("place an access map's points once each", () => {
    const md = accessModel(dir(), "org:so0");
    expect(new Set(md.nodes.map((n) => n.id)).size).toBe(md.nodes.length);
  });
  it("are found the same each time they are asked, in every organisation", () => {
    const d = dir();
    for (const o of catalog.orgs) {
      const fs = orgFindings(d, `org:${o.id}`);
      expect(fs.length).toBeGreaterThanOrEqual(0);
      expect(orgFindings(d, `org:${o.id}`)).toEqual(fs);
    }
  });
});

describe("the layout's indexes", () => {
  /// The walk as it was: every edge read at every step.
  function plainPaths(es: ReturnType<typeof orient>, id: string) {
    const nodes = new Set([id]);
    const edges = new Set<number>();
    const walk = (from: string, dir: 1 | -1) => {
      es.forEach((e, i) => {
        const [near, far] = dir > 0 ? [e.L, e.R] : [e.R, e.L];
        if (near === from && !edges.has(i)) {
          edges.add(i);
          nodes.add(far);
          walk(far, dir);
        }
      });
    };
    walk(id, 1);
    walk(id, -1);
    return { nodes, edges };
  }
  /// Vertical placement as it was: each point's neighbours read by a walk
  /// over every edge.
  function plainVertical(md: MapModel, height: number, t: { top: number; bottom: number; gap: number; maxStep: number }) {
    const near = (id: string) => md.edges.filter((e) => e.a === id || e.b === id).map((e) => (e.a === id ? e.b : e.a));
    const top = t.top;
    const bot = height - t.bottom;
    const pos = new Map<string, number>();
    const byLane = (l: number) => md.nodes.filter((n) => n.lane === l);
    const pl = byLane(md.pivot);
    const step = Math.max(t.gap, Math.min(t.maxStep, Math.floor((bot - top) / Math.max(1, pl.length - 1 || 1) / 8) * 8));
    const span = step * (pl.length - 1);
    pl.forEach((n, i) => pos.set(n.id, Math.round(top + (bot - top - span) / 2 + i * step)));
    const order = [...Array(md.lanes.length).keys()].filter((l) => l !== md.pivot).sort((a, b) => Math.abs(a - md.pivot) - Math.abs(b - md.pivot) || a - b);
    for (const l of order) {
      const list = byLane(l);
      if (!list.length) continue;
      const placedMax = pos.size ? Math.max(...pos.values()) : top - t.gap;
      const want = list.map((n) => {
        const ys = near(n.id).filter((x) => pos.has(x)).map((x) => pos.get(x)!);
        return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : placedMax + t.gap;
      });
      spread(want, t.gap, top, bot).forEach((y, i) => pos.set(list[i]!.id, y));
    }
    return pos;
  }
  it("walk the same paths through every point", () => {
    const md = accessModel(dir(), "org:so0");
    const es = orient(md);
    for (const p of md.nodes.slice(0, 120)) {
      const a = pathsThrough(es, p.id);
      const b = plainPaths(es, p.id);
      expect([...a.nodes]).toEqual([...b.nodes]);
      expect([...a.edges]).toEqual([...b.edges]);
    }
  });
  it("place the points where the plain walk placed them", () => {
    const t = { top: 72, bottom: 32, gap: 56, maxStep: 136 };
    const d = dir();
    for (const md of [accessModel(d, "org:so0"), accessModel(d, "org:so1"), mapModel(d, { kind: MapKind.Relations, anchor: "item:aws" })])
      for (const h of [600, 1200, 4000]) expect([...placeVertical(md, h, t)]).toEqual([...plainVertical(md, h, t)]);
  });
});

describe("empty folders", () => {
  const withEmpty = { ...DEMO, folders: [...DEMO.folders, { id: "nothing", name: "Nothing here" }, { id: "old", name: "Old stuff" }] };
  const dir = new Directory(withEmpty, []);

  it("go into one row of their own after the personal vault's folders and items", () => {
    const kids = dir.kidIds("personal");
    expect(kids.at(-1)).toBe(EMPTY_FOLDERS);
    expect(kids).not.toContain("folder:nothing");
    expect(dir.kidIds(EMPTY_FOLDERS)).toEqual(["folder:nothing", "folder:old"]);
  });

  it("live under that row on the path", () => {
    expect(dir.node("folder:nothing").home).toEqual(["personal", EMPTY_FOLDERS, "folder:nothing"]);
  });

  it("leave no such row where every folder holds something", () => {
    expect(new Directory(DEMO, []).has(EMPTY_FOLDERS)).toBe(DEMO.folders.some((f) => !DEMO.items.some((i) => !i.deleted && !i.orgId && i.folderId === f.id)));
  });
});
