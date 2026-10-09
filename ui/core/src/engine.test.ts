// The engine around the path: places, suggestions, findings, maps, verbs and
// documents, over the demo vault and the demo plugin.
import { describe, expect, it, beforeEach } from "vitest";
import { DEMO, DEMO_NOW } from "./demo";
import { demoContributions, DEMO_PLACES, DemoBackend } from "./demo-backend";
import { setLang, text, LANGS, type Text, Lang } from "./i18n";
import { Directory, MapKind } from "./path/directory";
import { Query, TokenKey } from "./path/query";
import { CORE_VERBS, previewOf } from "./verbs/core";
import { DEFAULT_PLACES, loadPlaces, storePlaces, currentPlace, placeFor, PLACE_KEY, type PlaceStore } from "./path/places";
import { suggest, take, OptionType } from "./path/suggest";
import { orgFindings } from "./model/findings";
import { mapModel, onMap } from "./map/model";
import { buildDoc } from "./doc/build";
import { PreviewKind } from "./verbs/spec";
import { Level, SecretField } from "./model/types";

const places = [...DEFAULT_PLACES, ...DEMO_PLACES];
const contribs = demoContributions();
const dir = () => new Directory(DEMO, contribs, { now: DEMO_NOW, places });
const query = () => new Query(dir(), [...CORE_VERBS, ...contribs.flatMap((c) => c.verbs ?? [])]);

/// Every text inside a value, wherever it sits.
function texts(v: unknown, out: Text[] = []): Text[] {
  if (Array.isArray(v)) v.forEach((x) => texts(x, out));
  else if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if ("label" in o && "secret" in o) return out;
    if (("key" in o && typeof o.key === "string" && !("itemId" in o)) || ("ext" in o && typeof o.ext === "string") || ("raw" in o && typeof o.raw === "string" && Object.keys(o).length === 1)) out.push(o as Text);
    else Object.values(o).forEach((x) => texts(x, out));
  }
  return out;
}

beforeEach(() => setLang(Lang.Ru));

describe("places", () => {
  const mem = (init: Record<string, string> = {}): PlaceStore & { m: Record<string, string> } => {
    const m = { ...init };
    return { m, getItem: (k) => m[k] ?? null, setItem: (k, v) => void (m[k] = v) };
  };
  const icons = new Set(["server", "person", "filter"]);
  it("keeps a person's place and reads it back", () => {
    const q = query();
    const p = placeFor(q, q.compile("acme state:critical"));
    expect(p.level).toBe("critical");
    const s = mem();
    expect(storePlaces(s, [...places, p])).toBe(true);
    const back = loadPlaces(s, icons);
    expect(back.problems).toEqual([]);
    expect(back.places.map((x) => x.line)).toEqual([p.line]);
  });
  it("reports stored places that do not parse, and loads none of them half", () => {
    expect(loadPlaces(mem({ [PLACE_KEY]: "{" }), icons).problems).toHaveLength(1);
    const r = loadPlaces(mem({ [PLACE_KEY]: JSON.stringify([{ name: "A", line: "x", icon: "server" }, { name: "", line: "y", icon: "server" }, { name: "B", line: "z", icon: "nope" }]) }), icons);
    expect(r.places.map((p) => p.line)).toEqual(["x"]);
    expect(r.problems).toHaveLength(2);
  });
  it("says a blocked store is blocked, not empty", () => {
    const blocked: PlaceStore = {
      getItem: () => {
        throw new Error("denied");
      },
      setItem: () => {
        throw new Error("denied");
      },
    };
    expect(loadPlaces(blocked, icons).problems[0]).toMatch(/blocked/);
    expect(storePlaces(blocked, places)).toBe(false);
  });
  it("knows when the path stands on a place", () => {
    const q = query();
    expect(currentPlace(q, q.compile("state:critical"), places)?.id).toBe("critical");
    expect(currentPlace(q, q.compile("acme"), places)).toBeNull();
  });
});

describe("suggestions", () => {
  it("offer the next steps, the places and the keys when nothing is typed", () => {
    const q = query();
    const opts = suggest(q, q.compile("acme"), "", places);
    expect(opts[0]!.type).toBe("step");
    expect(opts.some((o) => o.type === OptionType.Run && o.value === "state:critical")).toBe(true);
    expect(opts.some((o) => o.type === OptionType.Key && o.value === "state:")).toBe(true);
  });
  it("offer a key's values while it is typed", () => {
    const q = query();
    const opts = suggest(q, q.compile("acme"), "state:", places);
    expect(opts.map((o) => o.value)).toContain("state:critical");
    expect(opts.every((o) => o.type === OptionType.Token)).toBe(true);
  });
  it("mark the verbs that do not apply here", () => {
    const q = query();
    const opts = suggest(q, q.compile("acme"), "> ", places);
    expect(opts.find((o) => o.value === "rotate")!.na).toBe(true);
    expect(opts.find((o) => o.value === "invite")!.na).toBeUndefined();
  });
  it("take a step into the line and a verb after it", () => {
    const q = query();
    const st = q.compile("acme");
    const step = suggest(q, st, "", places).find((o) => o.type === OptionType.Step)!;
    expect(take(q, st, "", step)).toEqual({ line: `acme ${step.value}`, reopen: false });
    const v = suggest(q, st, "> inv", places)[0]!;
    expect(take(q, st, "> inv", v)).toEqual({ line: "acme > invite", reopen: false });
  });
  it("find a host by a mask of its zone", () => {
    const q = query();
    expect(suggest(q, q.compile(""), "host:", places).map((o) => o.value)).toContain("host:*.prod.*");
    expect(q.results("root", { tokens: [{ k: TokenKey.Host, v: "*.prod.*" }], words: [] })).toHaveLength(3);
  });
});

describe("findings", () => {
  it("name the member without a second factor who reaches something critical", () => {
    const fs = orgFindings(dir(), "org:acme");
    const first = fs[0]!;
    expect(first.level).toBe("critical");
    expect(first.focus).toBe("member:tomas");
    expect(fs.some((f) => f.focus === "item:travel" && f.level === Level.Critical)).toBe(true);
    expect(fs.some((f) => f.focus === "member:marco" && f.level === Level.Warning)).toBe(true);
    expect(fs.some((f) => f.title.toString() && f.level === Level.Action && f.doc && !f.map)).toBe(true);
    expect(fs.some((f) => f.level === Level.Unknown && f.map)).toBe(true);
  });
});

describe("maps", () => {
  it("draw an item's relations: its folder, its reused twin, its service and the cluster that takes its token", () => {
    const d = dir();
    const m = mapModel(d, { kind: MapKind.Relations, anchor: "item:aws" });
    expect(m.nodes.find((n) => n.anchor)!.id).toBe("item:aws");
    expect(m.edges.find((e) => e.b === "item:gitlab")).toMatchObject({ kind: "svc", level: "critical" });
    expect(m.edges.find((e) => e.b === "item:billing")).toMatchObject({ kind: "svc" });
    expect(m.nodes.some((n) => n.id === "k8s:prod-eu-1")).toBe(true);
    expect(m.lanes).toHaveLength(4);
  });
  it("draw an organisation's access: members, collections, items", () => {
    const m = mapModel(dir(), { kind: MapKind.Access, anchor: "org:acme" });
    expect(m.nodes.filter((n) => n.lane === 0)).toHaveLength(9);
    expect(m.nodes.filter((n) => n.lane === 1)).toHaveLength(3);
    expect(m.edges.find((e) => e.a === "member:tomas" && e.b === "collection:finance")).toMatchObject({ kind: "hidden", level: "critical", chip: true });
  });
  it("know their points", () => {
    const d = dir();
    expect(onMap(d, { kind: MapKind.Topology, anchor: "plugin:ssh" }, "ssh:host/db-1")).toBe(true);
    expect(onMap(d, { kind: MapKind.Access, anchor: "org:acme" }, "item:aws")).toBe(false);
  });
});

describe("verbs", () => {
  it("preview what they will do, and name what the backend is asked for", () => {
    const d = dir();
    const p = previewOf(d, CORE_VERBS, "copy password", "item:aws", "");
    expect(p.kind).toBe("ready");
    if (p.kind === PreviewKind.Ready) expect(p.effect).toEqual({ copy: { itemId: "aws", field: "password" } });
  });
  it("say when the object does not fit, offering one that does", () => {
    const p = previewOf(dir(), CORE_VERBS, "rotate", "org:acme", "");
    expect(p).toMatchObject({ kind: "pick", obj: "org:acme" });
    if (p.kind === PreviewKind.Pick) expect(p.example).toMatch(/^item:/);
  });
  it("say when there is no such verb", () => {
    expect(previewOf(dir(), CORE_VERBS, "fly", null, "").kind).toBe("unknown");
  });
});

describe("documents", () => {
  it("can be built for every node, and every word in them reads in both languages", async () => {
    const d = dir();
    const backend = new DemoBackend();
    for (const n of d.all()) {
      if (n.map) continue;
      const detail = n.item ? await backend.item(n.item.id) : null;
      const doc = buildDoc({ dir: d, detail, server: "vault.demo.example", places }, n.id);
      for (const l of LANGS) {
        setLang(l);
        for (const x of texts(doc)) expect(() => text(x)).not.toThrow();
      }
    }
  });
  it("show a password as a secret, never as a value", async () => {
    const d = dir();
    const detail = await new DemoBackend().item("aws");
    const doc = buildDoc({ dir: d, detail, server: "s", places }, "item:aws");
    const blocks = doc.sections.flatMap((s) => s.blocks);
    expect(blocks.some((b) => "secret" in b && b.secret.key === "password")).toBe(true);
    expect(blocks.some((b) => "totp" in b), "the one-time code is the editor's, not the page's").toBe(false);
  });
  it("read every map and preview in both languages", () => {
    const d = dir();
    const q = query();
    const maps = [
      { kind: MapKind.Relations, anchor: "item:aws" },
      { kind: MapKind.Relations, anchor: "item:key-prod" },
      { kind: MapKind.Access, anchor: "org:acme" },
      { kind: MapKind.Topology, anchor: "plugin:ssh" },
    ];
    for (const l of LANGS) {
      setLang(l);
      for (const m of maps) for (const x of texts(mapModel(d, m))) expect(() => text(x)).not.toThrow();
      for (const v of q.verbs) for (const obj of ["item:aws", "org:acme", "ssh:host/db-1", "plugin:ssh", null]) for (const x of texts(previewOf(d, q.verbs, v.id, obj, ""))) expect(() => text(x)).not.toThrow();
    }
  });
});

describe("the demo backend", () => {
  it("reveals only made-up values and refuses to read one after it is dropped", async () => {
    const r = await new DemoBackend().reveal({ itemId: "aws", field: SecretField.Password });
    expect(r.value).toMatch(/^demo-/);
    r.drop();
    expect(() => r.value).toThrow();
  });
});
