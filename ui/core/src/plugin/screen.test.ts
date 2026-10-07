// A plugin's declared screens as the core reads them: the wire's words become
// the core's texts and members, and whatever does not hold together is
// refused by the plugin's name — an unknown node, a word its dictionary
// lacks, an icon the window does not have, a secret echoed into a form, a
// word to type outside a danger zone.
import { describe, expect, it } from "vitest";
import { Lang, type Words } from "../i18n";
import { ICONS } from "../ui/Icons";
import { CellType, FieldKind, ScreenNodeType, StreamState, Tone, screenReader } from "./screen";
import { contributionOf, type DeclaredPlaces } from "./declared";
import { Level } from "../model/types";

const WORDS: Words = {
  [Lang.Ru]: { pods: "Поды", name: "Имя", open: "Открыть", del: "Удалить", hint: "Насовсем", token: "Токен" },
  [Lang.En]: { pods: "Pods", name: "Name", open: "Open", del: "Delete", hint: "For good", token: "Token" },
};
const read = () => screenReader("kube", { words: WORDS, icons: ICONS });

const page = {
  title: { key: "pods" },
  icon: "cube",
  subtitle: { raw: "https://127.0.0.1:6443" },
  switcher: { current: "a", items: [{ key: "b", label: { raw: "b" }, route: "cluster/b" }], add: { label: { key: "open" }, icon: "plus", title: { key: "open" }, action: { op: "add" } } },
  actions: [{ icon: "refresh", title: { key: "open" }, action: { op: "refresh" } }],
  refresh_ms: 10000,
  body: [
    {
      type: "tabs",
      id: "groups",
      icons_only: true,
      tabs: [{ id: "pods", title: { key: "pods" }, icon: "stack", load: { op: "table", payload: { kind: "pods" } }, refresh_ms: 5000 }],
    },
    {
      type: "table",
      id: "t",
      columns: [{ id: "name", title: { key: "name" }, sortable: true }],
      facets: [{ id: "ns", title: { key: "name" }, icon: "folder" }],
      rows: [{ key: "a", cells: { name: { type: "chip", chip: { label: { raw: "api" }, tone: "ok", dot: true } } }, facets: { ns: "prod" }, sort: { name: 1 }, open: { op: "object" } }],
    },
    { type: "danger", title: { key: "del" }, hint: { key: "hint" }, button: { label: { key: "del" }, title: { key: "del" }, tone: "bad", action: { op: "delete", confirm: "api" } } },
  ],
};

describe("a plugin's screen", () => {
  it("is read into the core's words and members", () => {
    const p = read().page(page, "cluster/a");
    expect(p.title).toEqual({ ext: "kube.pods" });
    expect(p.refreshMs).toBe(10000);
    // The switcher's other clusters are the path's column; its "add" stays.
    expect(p.actions.map((b) => b.action.op)).toEqual(["refresh", "add"]);
    const [tabs, table, danger] = p.body;
    expect(tabs).toMatchObject({ type: ScreenNodeType.Tabs, iconsOnly: true, tabs: [{ id: "pods", refreshMs: 5000, load: { op: "table", payload: { kind: "pods" } } }] });
    expect(table).toMatchObject({ type: ScreenNodeType.Table, rows: [{ key: "a", facets: { ns: "prod" }, cells: { name: { type: CellType.Chip, chip: { tone: Tone.Ok, dot: true } } } }] });
    expect(danger).toMatchObject({ type: ScreenNodeType.Danger, button: { tone: Tone.Bad, action: { confirm: "api" } } });
  });

  it("refuses what does not hold together, by the plugin's name", () => {
    const spoil = (f: (p: typeof page & Record<string, unknown>) => void) => {
      const p = structuredClone(page) as typeof page & Record<string, unknown>;
      f(p);
      return () => read().page(p, "cluster/a");
    };
    expect(spoil((p) => p.body.push({ type: "marquee" } as never))).toThrow(/the plugin "kube" answered a node of an unknown kind "marquee"/);
    expect(spoil((p) => (p.title = { key: "nowhere" }))).toThrow(/"nowhere".*lacks/);
    expect(spoil((p) => (p.icon = "unicorn"))).toThrow(/the icon "unicorn"/);
    expect(spoil((p) => ((p.body[1] as { rows: { cells: Record<string, unknown> }[] }).rows[0]!.cells.age = { type: "empty" }))).toThrow(/a cell "age".*no column/);
    expect(spoil((p) => (p.actions[0]!.action = { op: "x", confirm: "api" } as never))).toThrow(/typed outside a danger zone/);
    expect(spoil((p) => p.body.push({ type: "form", fields: [{ id: "t", label: { key: "token" }, kind: { kind: "secret" }, value: "hunter2" }], submit: { label: { key: "open" }, title: { key: "open" }, action: { op: "go" } } } as never))).toThrow(
      /a secret is never echoed into a form/,
    );
    expect(spoil((p) => ((p.body[0] as { on?: string }).on = "logs"))).toThrow(/open on "logs"/);
  });

  it("reads a form's fields with their kinds", () => {
    const p = read().page(
      {
        title: { key: "pods" },
        body: [
          {
            type: "form",
            fields: [
              { id: "name", label: { key: "name" }, kind: { kind: "text" } },
              { id: "n", label: { key: "name" }, kind: { kind: "number", min: 0, max: 9 } },
              { id: "token", label: { key: "token" }, kind: { kind: "secret" } },
              { id: "ns", label: { key: "name" }, kind: { kind: "select", options: [["a", { raw: "a" }]] } },
            ],
            submit: { label: { key: "open" }, title: { key: "open" }, primary: true, action: { op: "send" } },
          },
        ],
      },
      "add",
    );
    expect(p.body[0]).toMatchObject({ type: ScreenNodeType.Form, fields: [{ spec: { kind: FieldKind.Text } }, { spec: { kind: FieldKind.Number, min: 0, max: 9 } }, { spec: { kind: FieldKind.Secret } }, { spec: { kind: FieldKind.Select } }] });
  });
});

describe("a plugin's reply", () => {
  it("says where to go, what to open and what to say", () => {
    const r = read().reply({ go: "cluster/b", drawer: { title: { raw: "pod" }, body: [] }, close_dialog: true, toast: { key: "open" }, refresh: true }, "object");
    expect(r).toMatchObject({ go: "cluster/b", drawer: { title: { raw: "pod" } }, closeDialog: true, closeDrawer: false, toast: { ext: "kube.open" }, refresh: true, data: null });
  });

  it("carries a stream and its output, and refuses a state it does not know", () => {
    const rd = read();
    expect(rd.stream({ stream: "s1" }, "shell_open")).toBe("s1");
    expect(rd.chunk({ data: "aGk=", cursor: 2, state: "open", dropped: false }, "shell_read")).toEqual({ data: "aGk=", cursor: 2, state: StreamState.Open, error: null });
    expect(() => rd.chunk({ cursor: 0, state: "half-open" }, "shell_read")).toThrow(/stream state "half-open"/);
    expect(rd.diff({ before: null, after: "kind: Pod" }, "check")).toEqual({ before: null, after: "kind: Pod" });
  });
});

describe("a place that opens a screen", () => {
  const places = (screens: Record<string, string | undefined>, primary?: string): DeclaredPlaces => ({
    root: { id: "", icon: "cube", title: { raw: "Kubernetes" }, level: Level.Healthy, kids: [{ type: "place" as never, id: "c1" }], ...(screens[""] !== undefined ? { screen: screens[""] } : {}) },
    places: [
      { id: "c1", parent: "", icon: "cube", title: { raw: "c1" }, level: Level.Healthy, ...(screens.c1 !== undefined ? { screen: screens.c1 } : {}), page: { sections: [], ...(primary ? { primary } : {}) } },
    ],
    ...(primary ? { verbs: [{ id: primary, name: { key: "open" }, uses: [{ on: { place: "c1" }, action: { op: "look" } }], preview: { lede: { key: "open" }, go: { key: "open" } } }] } : {}),
  });

  it("offers it on its page, as the main action where there is none", () => {
    const c = contributionOf("kube", places({ c1: "cluster/c1", "": "" }), { words: WORDS, icons: ICONS });
    expect(c.screens).toEqual({ "cluster/c1": "kube:c1", "": "plugin:kube" });
    const doc = c.nodes[0]!.doc!(null as never);
    expect(doc.hero.primary?.act).toEqual({ screen: { node: "kube:c1", plugin: "kube", route: "cluster/c1" } });
  });

  it("puts it beside a main verb", () => {
    const c = contributionOf("kube", places({ c1: "cluster/c1" }, "look"), { words: WORDS, icons: ICONS });
    const doc = c.nodes[0]!.doc!(null as never);
    expect(doc.hero.primary?.act).toEqual({ verb: "look" });
    expect(doc.hero.more?.[0]?.act).toEqual({ screen: { node: "kube:c1", plugin: "kube", route: "cluster/c1" } });
  });

  it("is refused when two places open one screen", () => {
    expect(() => contributionOf("kube", places({ c1: "x", "": "x" }), { words: WORDS, icons: ICONS })).toThrow(/the screen "x" opened by two places/);
  });
});
