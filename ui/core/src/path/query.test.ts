import { describe, expect, it, beforeEach } from "vitest";
import { DEMO, DEMO_NOW } from "../demo";
import { setLang, Lang } from "../i18n";
import { Directory, NodeKind, MapKind } from "./directory";
import { Query, columns, crumbs, fold, answerOf, rows, isStep, type Segment, type Verb, TokenKey } from "./query";
import { PathStore } from "./store";
import { type Catalog, ItemKind, Level } from "../model/types";

const verbs: Verb[] = [
  { id: "rotate", name: { key: "verb.rotate" }, applies: (n) => n?.item?.kind === ItemKind.Login },
  { id: "copy password", name: { key: "verb.copyPassword" }, applies: (n) => n?.item?.kind === ItemKind.Login },
  { id: "invite", name: { key: "verb.invite" }, applies: (n) => n?.kind === NodeKind.Org || n?.kind === NodeKind.Member },
];
const dir = (c: Catalog = DEMO) => new Directory(c, [], { now: DEMO_NOW });
const q = (c: Catalog = DEMO) => new Query(dir(c), verbs);
const ids = (segs: Segment[]) => segs.map((s) => ("id" in s ? s.id : "filter"));

beforeEach(() => setLang(Lang.Ru));

describe("the graph", () => {
  it("homes every item under its place", () => {
    const withTrash: Catalog = { ...DEMO, items: DEMO.items.map((i) => (i.id === "wifi" ? { ...i, deleted: true } : i)) };
    const d = dir(withTrash);
    expect(d.node("item:aws").home).toEqual(["personal", "folder:work", "item:aws"]);
    expect(d.node("item:travel").home).toEqual(["org:acme", "org:acme/collections", "collection:finance", "item:travel"]);
    expect(d.node("item:wifi").home).toEqual(["trash", "item:wifi"]);
  });
  it("finds no trashed item by a search", () => {
    const withTrash: Catalog = { ...DEMO, items: DEMO.items.map((i) => (i.id === "travel" ? { ...i, deleted: true } : i)) };
    const query = q(withTrash);
    const found = query.results("root", { tokens: [{ k: TokenKey.State, v: "critical" }], words: [] });
    expect(found).not.toContain("item:travel");
  });
  it("gives every node a unique slug", () => {
    const d = dir();
    const slugs = d.all().filter((n) => n.id !== "root").map((n) => n.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
  });
  it("shows a member what they reach first, then what is closed to them", () => {
    const kids = dir().kids("member:dana");
    expect(kids.filter(isStep).map((k) => [k.id, k.off ?? false])).toEqual([
      ["collection:platform", false],
      ["collection:shared", false],
      ["collection:finance", true],
    ]);
    expect(kids.filter((k) => "heading" in k)).toHaveLength(2);
  });
  it("lays the root out in groups: the whole vault, owners, then saved places", () => {
    const d = new Directory(DEMO, [], { now: DEMO_NOW, places: [{ id: "x", name: { raw: "X" }, line: "state:critical", level: Level.Critical }] });
    const shape = d.kids("root").map((e) => ("id" in e ? e.id : "gap" in e ? "·" : "place" in e ? `place:${e.place}` : "heading"));
    expect(shape).toEqual(["all", "·", "personal", "org:acme", "org:globex", "heading", "place:x"]);
  });
  it("counts what a folder holds instead of a second line", () => {
    const d = dir();
    expect(d.node("folder:work").count).toBe(3);
    expect(d.node("folder:work").sub).toBeUndefined();
    expect(d.node("org:acme/members").count).toBe(9);
  });
  it("adds an organisation's policies where it sees them", () => {
    const d = dir();
    expect(d.kidIds("org:acme")).toContain("org:acme/policies");
    expect(d.kidIds("org:globex")).not.toContain("org:globex/policies");
    expect(d.node("org:acme/policies").level).toBe("action");
  });
  it("says why an item stands where it does, naming the other half of a reuse", () => {
    const d = dir();
    expect(d.node("item:aws").why).toEqual({ key: "why.reusedWith", args: { name: "GitLab — platform" } });
    expect(d.node("item:stripe").level).toBe("action");
    expect(d.node("item:travel").level).toBe("critical");
  });
});

describe("the line", () => {
  it("walks a path of slugs and writes it back the same", () => {
    const query = q();
    const st = query.compile("acme › acme-members › dana-whitfield");
    expect(st.segs).toEqual([{ id: "org:acme" }, { id: "org:acme/members" }, { id: "member:dana" }]);
    expect(query.serialize(st)).toBe("acme › acme-members › dana-whitfield");
  });
  it("re-roots a step that is not next at its home", () => {
    const st = q().compile("travel-company-card");
    expect(ids(st.segs)).toEqual(["org:acme", "org:acme/collections", "collection:finance", "item:travel"]);
  });
  it("reaches a section by its name in either language", () => {
    const query = q();
    expect(query.compile("acme участники").segs.at(-1)).toEqual({ id: "org:acme/members" });
    expect(query.compile("acme members").segs.at(-1)).toEqual({ id: "org:acme/members" });
  });
  it("turns a filter into a results column, most serious first", () => {
    const query = q();
    const st = query.compile("state:critical");
    const cols = columns(query, st.segs, st.map);
    expect(cols).toHaveLength(1);
    expect(cols[0]!.type).toBe("results");
    const found = rows(query, cols[0]!).filter(isStep).map((r) => r.id);
    expect(found).toContain("item:aws");
    expect(found).toContain("item:gitlab");
    expect(answerOf(st, cols).kind).toBe("list");
  });
  it("continues the path from a result", () => {
    const query = q();
    const st = query.compile("state:critical › aws-production");
    expect(st.segs).toHaveLength(2);
    expect(answerOf(st, columns(query, st.segs, st.map))).toEqual({ kind: "document", id: "item:aws" });
  });
  it("keeps a filter inside the place it was typed in", () => {
    const query = q();
    const st = query.compile("acme state:attention");
    const found = rows(query, columns(query, st.segs, st.map).at(-1)!).filter(isStep).map((r) => r.id);
    expect(found.every((id) => id.startsWith("item:") || id.startsWith("member:"))).toBe(true);
    expect(found).toContain("item:travel");
    expect(found).not.toContain("item:aws");
  });
  it("reads a verb at the end", () => {
    const query = q();
    const st = query.compile("aws-production > rotate");
    expect(st.verb).toBe("rotate");
    expect(query.serialize(st)).toBe("personal › work › aws-production > rotate");
    expect(query.verbsFor(st).map((v) => v.id)).toEqual(["rotate", "copy password"]);
  });
  it("opens an organisation's access map from its row", () => {
    const st = q().compile("acme › acme-access");
    expect(st.map).toEqual({ kind: "access", anchor: "org:acme" });
  });
  it("keeps a map only while the object is one of its points", () => {
    const query = q();
    expect(query.compile("acme › acme-members › dana-whitfield map:acme-access").map).toEqual({ kind: "access", anchor: "org:acme" });
    expect(query.compile("aws-production map:aws-production").map).toEqual({ kind: "relations", anchor: "item:aws" });
    // GitLab is on AWS's relations map: the map stays when the path steps there.
    const st = query.compile("personal › work › gitlab-platform map:aws-production");
    expect(st.map).toEqual({ kind: "relations", anchor: "item:aws" });
    // Finance holds AWS's twin of service: on the map, so the path stands there.
    const fin = query.compile("acme › acme-collections › finance map:aws-production");
    expect(fin.map).toEqual({ kind: "relations", anchor: "item:aws" });
    expect(fin.segs.at(-1)).toEqual({ id: "collection:finance" });
    // Stripe is not: the map goes.
    expect(query.compile("personal › work › stripe-finance").map).toBeNull();
  });
});

describe("the crumbs", () => {
  it("speak human names, never syntax", () => {
    const query = q();
    const cs = crumbs(query, query.compile("acme state:critical > rotate")).map((c) => c.name);
    expect(cs).toEqual(["Хранилище", "Acme", "Состояние: Критично", "Сменить пароль"]);
    for (const c of cs) expect(c).not.toMatch(/[a-z]+:|>/);
  });
  it("have no Cyrillic in English", () => {
    setLang(Lang.En);
    const query = q();
    for (const line of ["acme › acme-members › dana-whitfield", "state:attention", "acme › acme-access", "aws-production > rotate"]) {
      for (const c of crumbs(query, query.compile(line))) expect(c.name).not.toMatch(/\p{Script=Cyrillic}/u);
    }
  });
});

describe("folding", () => {
  const open = (r: boolean[]) => r.map((x, i) => (x ? i : -1)).filter((i) => i >= 0);
  it("keeps the last two columns open", () => {
    expect(open(fold(5, { map: false, narrow: false, fits: () => true }))).toEqual([3, 4]);
  });
  it("keeps one with a map, in a narrow window, or when two do not fit", () => {
    expect(open(fold(4, { map: true, narrow: false, fits: () => true }))).toEqual([3]);
    expect(open(fold(4, { map: false, narrow: true, fits: () => true }))).toEqual([3]);
    expect(open(fold(4, { map: false, narrow: false, fits: (n) => n < 2 }))).toEqual([3]);
  });
  it("never leaves a spine after an open column", () => {
    for (let n = 1; n < 7; n++) {
      const r = fold(n, { map: false, narrow: false, fits: () => true });
      expect(r.join("")).not.toMatch(/true.*false/);
    }
  });
});

describe("the store", () => {
  it("unfolds a spine without touching the path, and the next step folds it back", () => {
    const s = new PathStore(q(), "acme › acme-members › dana-whitfield");
    const line = s.get().line;
    s.expand(0);
    expect(s.get().line).toBe(line);
    expect(s.get().canBack).toBe(false);
    expect(s.get().shown).toBe(0);
    expect(s.get().focus).toBe(0);
    s.commit("personal");
    expect(s.get().shown).toBeNull();
    expect(() => s.expand(9)).toThrow();
  });
  it("moves the open pair onto an unfolded column, from either side", () => {
    const open = (r: boolean[]) => r.map((x, i) => (x ? i : -1)).filter((i) => i >= 0);
    const base = { map: false, narrow: false, fits: () => true };
    expect(open(fold(5, { ...base, shown: 0 }))).toEqual([0, 1]);
    expect(open(fold(5, { ...base, shown: 1 }))).toEqual([1, 2]);
    expect(open(fold(5, { ...base, shown: 4 }))).toEqual([3, 4]);
    expect(open(fold(5, { ...base, shown: 3 }))).toEqual([3, 4]);
    expect(open(fold(5, { ...base, map: true, shown: 1 }))).toEqual([1]);
  });
  it("walks a column with the arrows without making history", () => {
    const s = new PathStore(q(), "personal › work › aws-production");
    expect(s.get().focus).toBe(2);
    s.move(1);
    expect(ids(s.get().state.segs)).toEqual(["personal", "folder:work", "item:stripe"]);
    expect(s.get().canBack).toBe(false);
    s.left();
    expect(s.get().focus).toBe(1);
    expect(ids(s.get().state.segs)).toEqual(["personal", "folder:work"]);
    s.right();
    expect(s.get().focus).toBe(2);
    expect(ids(s.get().state.segs)).toEqual(["personal", "folder:work", "item:gitlab"]);
  });
  it("keeps the map while a chosen row is on it", () => {
    const s = new PathStore(q(), "personal › work › aws-production map:aws-production");
    s.choose(2, "item:gitlab");
    expect(s.get().state.map).toEqual({ kind: "relations", anchor: "item:aws" });
    s.choose(2, "item:stripe");
    expect(s.get().state.map).toBeNull();
  });
  it("closes a map that is a row of its own by stepping back off it", () => {
    const s = new PathStore(q(), "acme › acme-access");
    s.closeMap();
    expect(ids(s.get().state.segs)).toEqual(["org:acme"]);
    expect(s.get().state.map).toBeNull();
  });
  it("opens an access map from a place that is not on it at the map's own row", () => {
    const s = new PathStore(q(), "acme");
    s.openMap({ kind: MapKind.Access, anchor: "org:acme" });
    expect(ids(s.get().state.segs)).toEqual(["org:acme", "org:acme/access"]);
  });
  it("gives a filter's last piece back to the line", () => {
    const s = new PathStore(q(), "state:critical aws");
    expect(s.unwind()).toBe("aws");
    expect(s.get().line).toBe("state:critical");
    expect(s.unwind()).toBe("state:critical");
    expect(s.get().line).toBe("");
  });
  it("drops a step that vanished when the catalogue changes", () => {
    const s = new PathStore(q(), "personal › work › aws-production");
    s.rebase(q({ ...DEMO, items: DEMO.items.filter((i) => i.id !== "aws") }));
    expect(s.get().state.segs.some((x) => "id" in x && x.id === "item:aws")).toBe(false);
  });
});
