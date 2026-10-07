// A plugin's places, as it declares them (keyward-ui's `places`, in Rust),
// made into what the path walks: nodes with their homes and rows, pages in
// the core's vocabulary, verbs with previews, findings about items, lines to
// items and a map. Pure: the backend fetches the declaration, this reads it.
// A plugin ships no code for any of it; whatever does not hold together is
// refused here, by the plugin's name, rather than drawn half.
import type { Text, Words } from "../i18n";
import { type Action, type Block, type DocSpec, Hue, type MarkSpec, type Section, LeadTile } from "../doc/spec";
import { type DeclaredText, wordReader } from "./words";
import { type Link, type MapModel, EdgeKind } from "../map/types";
import { pointOf } from "../map/model";
import { Level, type LoudLevel } from "../model/types";
import { isEnumValue } from "../model/enum";
import type { ExtraSignal } from "../model/reasons";
import { slugify, type Contribution, type Directory, type Entry, type Node, ResultGroup, NodeKind, MapKind } from "../path/directory";
import type { Verb } from "../path/query";
import { type Input, type Preview, PreviewKind } from "../verbs/spec";

export type { DeclaredText } from "./words";
export type DeclaredTarget = { place: string } | { item: string };
export type DeclaredMark = { level: Level; text: DeclaredText };
/// What a declared row is. The declaration rides the wire as JSON; a row of
/// any other type is refused where it is read (`contributionOf`).
export enum DeclaredKidType {
  Place = "place",
  Item = "item",
  Heading = "heading",
  Gap = "gap",
}
export type DeclaredKid =
  | { type: DeclaredKidType.Place; id: string; sub?: DeclaredText }
  | { type: DeclaredKidType.Item; id: string; sub?: DeclaredText }
  | { type: DeclaredKidType.Heading; title: DeclaredText }
  | { type: DeclaredKidType.Gap };
/// What a declared block of a page is; refused where it is read otherwise.
export enum DeclaredBlockType {
  Field = "field",
  Ref = "ref",
  Finding = "finding",
  Para = "para",
  MapDoor = "map_door",
}
export type DeclaredBlock =
  | { type: DeclaredBlockType.Field; label: DeclaredText; value: DeclaredText; mono?: boolean; mark?: DeclaredMark }
  | { type: DeclaredBlockType.Ref; to: DeclaredTarget; title?: DeclaredText; context?: DeclaredText; mark?: DeclaredMark; mono?: boolean }
  | { type: DeclaredBlockType.Finding; level: Level; title: DeclaredText; sub?: DeclaredText; to?: DeclaredTarget }
  | { type: DeclaredBlockType.Para; text: DeclaredText }
  | { type: DeclaredBlockType.MapDoor; title: DeclaredText; sub: DeclaredText };
export type DeclaredSection = { title: DeclaredText; count?: number; blocks: DeclaredBlock[] };
export type DeclaredDoc = { what?: DeclaredText; state?: DeclaredMark; primary?: string; more?: string[]; map?: boolean; sections: DeclaredSection[]; note?: DeclaredText };
export type DeclaredPlace = {
  id: string;
  /// The place it lives under; `""` is the plugin's root; absent on the root.
  parent?: string;
  slug?: string;
  icon: string;
  title: DeclaredText;
  row_title?: DeclaredText;
  subtitle?: DeclaredText;
  count?: number;
  level: Level;
  why?: DeclaredText;
  short?: DeclaredText;
  mono?: boolean;
  sub_mono?: boolean;
  wide?: boolean;
  hue?: string;
  kids?: DeclaredKid[];
  find?: { group: ResultGroup.Hosts | ResultGroup.Clusters; kind: string; words: string };
  map?: boolean;
  page?: DeclaredDoc;
  /// The route of the plugin's declared screen the place opens.
  screen?: string;
};
export type DeclaredAction = { op: string; payload?: unknown; confirm?: string; twice?: boolean };
export type DeclaredVerb = {
  id: string;
  name: DeclaredText;
  icon?: string;
  uses: { on: DeclaredTarget; action: DeclaredAction }[];
  preview: { lede: DeclaredText; steps?: [DeclaredText, DeclaredText][]; go: DeclaredText; note?: DeclaredText; danger?: boolean };
};
export type DeclaredTopology = {
  title: DeclaredText;
  place: DeclaredText;
  lanes: DeclaredText[];
  pivot: number;
  points: { at: DeclaredTarget; lane: number }[];
  edges: { a: DeclaredTarget; b: DeclaredTarget; kind: EdgeKind; level?: LoudLevel; words: DeclaredText; chip?: boolean }[];
  findings?: { level: Level; text: DeclaredText; focus: DeclaredTarget }[];
  legend?: { kind: EdgeKind; level?: LoudLevel; text: DeclaredText }[];
};
/// Everything a plugin adds to the path, as it rides the wire.
export type DeclaredPlaces = {
  root: DeclaredPlace;
  places?: DeclaredPlace[];
  marks?: { item: string; level: Level; why: DeclaredText; short: DeclaredText }[];
  lines?: { from: string; item: string; kind: EdgeKind; level?: LoudLevel; words: DeclaredText; short: DeclaredText }[];
  verbs?: DeclaredVerb[];
  topology?: DeclaredTopology;
  /// Ask again in this many milliseconds.
  refresh_ms?: number;
};

export type DeclaredOptions = {
  /// The plugin's dictionary; every key it declares must be in it.
  words?: Words;
  /// The icons the window has; a name outside them is refused.
  icons?: ReadonlySet<string>;
  /// Verb words already taken (the core's, other plugins'): a plugin's verb
  /// may not shadow one.
  taken?: ReadonlySet<string>;
};

/// The search groups a plugin's place may be found under.
const GROUPS: ReadonlySet<string> = new Set<ResultGroup>([ResultGroup.Hosts, ResultGroup.Clusters]);

/// The node id of a plugin's root.
export const pluginRootId = (plugin: string) => `plugin:${plugin}`;

/// A plugin's declaration as a contribution to the path. Throws, naming the
/// plugin and the place, on anything that does not hold together.
export function contributionOf(plugin: string, d: DeclaredPlaces, opts: DeclaredOptions = {}): Contribution {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(plugin)) throw new Error(`a plugin's id "${plugin}" is not a word of the path`);
  const fail = (what: string): never => {
    throw new Error(`the plugin "${plugin}" declares ${what}`);
  };
  const rootId = pluginRootId(plugin);
  const words = opts.words;
  const { text, opt } = wordReader(plugin, words, fail);
  // boundary: the declaration's words become members here, or the plugin is refused.
  const level = (l: unknown, where: string): Level => (isEnumValue(Level, l) ? l : fail(`the level "${String(l)}" for ${where}`));
  const icon = (i: unknown, where: string): string => {
    if (typeof i !== "string" || !i) return fail(`no icon for ${where}`);
    if (opts.icons && !opts.icons.has(i)) fail(`the icon "${i}" for ${where}, which the window does not have`);
    return i;
  };
  const mark = (m: DeclaredMark | undefined, where: string): MarkSpec | undefined => (m ? { level: level(m.level, where), text: text(m.text, where) } : undefined);
  // boundary: a line's kind, from the declaration's word.
  const edge = (k: unknown, where: string): EdgeKind => (isEnumValue(EdgeKind, k) ? k : fail(`the line kind "${String(k)}" for ${where}`));
  // boundary: a line's colour, from the declaration's word.
  const loud = (l: unknown, where: string): LoudLevel | undefined => (l === undefined || l === null ? undefined : l === Level.Critical || l === Level.Warning ? l : fail(`the line colour "${String(l)}" for ${where}`));

  // The places, by id; the root is "".
  const r = d.root;
  if (!r || r.id !== "" || r.parent !== undefined) fail("a root that is not the root (it has an id or a parent)");
  const declared = new Map<string, DeclaredPlace>([["", r]]);
  for (const p of d.places ?? []) {
    if (!p.id) fail("a place with no id");
    if (typeof p.parent !== "string") fail(`the place "${p.id}" with no parent`);
    if (declared.has(p.id)) fail(`the place "${p.id}" twice`);
    declared.set(p.id, p);
  }
  const nodeId = (place: string) => (place === "" ? rootId : `${plugin}:${place}`);
  const placeNode = (id: string, where: string): string => (declared.has(id) ? nodeId(id) : fail(`${where} pointing at the place "${id}", which it does not declare`));
  const target = (t: DeclaredTarget, where: string): string => {
    if (t && typeof t === "object" && "place" in t) return placeNode(t.place, where);
    if (t && typeof t === "object" && "item" in t && typeof t.item === "string" && t.item) return `item:${t.item}`;
    return fail(`${where} pointing at nothing`);
  };

  // Homes: the chain of parents up to the root.
  const homes = new Map<string, string[]>([["", [rootId]]]);
  const homeOf = (id: string, seen: Set<string> = new Set()): string[] => {
    const known = homes.get(id);
    if (known) return known;
    if (seen.has(id)) fail(`the place "${id}" under itself`);
    seen.add(id);
    const parent = declared.get(id)!.parent!;
    if (!declared.has(parent)) fail(`the place "${id}" under "${parent}", which it does not declare`);
    const home = [...homeOf(parent, seen), nodeId(id)];
    homes.set(id, home);
    return home;
  };
  for (const id of declared.keys()) homeOf(id);

  // Slugs: the plugin's own, unique among its places; the graph makes them
  // unique beyond.
  const slugs = new Set<string>();
  const slugOf = (p: DeclaredPlace): string => {
    const base = p.id === "" ? plugin : slugify(p.slug ?? ("raw" in p.title ? p.title.raw : p.id)) || slugify(p.id) || "place";
    let s = base;
    for (let i = 2; slugs.has(s); i++) s = `${base}-${i}`;
    slugs.add(s);
    return s;
  };

  // Verbs, by word; the pages name them.
  const taken = opts.taken ?? new Set<string>();
  const verbs = new Map<string, Verb>();
  const usesOf = new Map<string, Set<string>>();
  for (const v of d.verbs ?? []) {
    const where = `the verb "${v.id}"`;
    if (typeof v.id !== "string" || !v.id.trim() || v.id !== v.id.trim()) fail(`a verb with an empty or padded word "${v.id}"`);
    if (verbs.has(v.id)) fail(`${where} twice`);
    if (taken.has(v.id)) fail(`${where}, which is already the window's or another plugin's`);
    if (!v.uses?.length) fail(`${where} with nowhere it applies`);
    const name = text(v.name, where);
    const vIcon = v.icon === undefined ? undefined : icon(v.icon, where);
    const pv = v.preview;
    const lede = text(pv.lede, `${where}'s preview`);
    const go = text(pv.go, `${where}'s preview`);
    const note = opt(pv.note, `${where}'s preview`);
    const steps = (pv.steps ?? []).map(([t, s]) => ({ title: text(t, `${where}'s steps`), sub: text(s, `${where}'s steps`) }));
    const on = new Map<string, { op: string; payload: unknown; confirm?: string }>();
    for (const u of v.uses) {
      const id = target(u.on, where);
      if (on.has(id)) fail(`${where} twice on "${id}"`);
      if (typeof u.action?.op !== "string" || !u.action.op) fail(`${where} with no operation on "${id}"`);
      on.set(id, { op: u.action.op, payload: u.action.payload ?? null, ...(u.action.confirm ? { confirm: u.action.confirm } : {}) });
    }
    usesOf.set(v.id, new Set(on.keys()));
    const first = on.keys().next().value!;
    verbs.set(v.id, {
      id: v.id,
      name,
      ...(vIcon ? { icon: vIcon } : {}),
      applies: (n: Node | null) => !!n && on.has(n.id),
      example: () => first,
      preview: (_dir: Directory, obj: string, arg: string): Preview => {
        const use = on.get(obj);
        if (!use) throw new Error(`the verb "${v.id}" of "${plugin}" does not apply to "${obj}"`);
        // A word to type before it goes: the preview asks for it and holds ↵
        // until it is typed.
        const form = use.confirm
          ? [{ inputs: [{ id: "confirm", label: { key: "plugin.typeToConfirm", args: { word: use.confirm } }, text: arg, mono: true, with: (x: string) => x } satisfies Input] }]
          : undefined;
        return {
          kind: PreviewKind.Ready,
          target: obj,
          title: name,
          lede,
          steps,
          go,
          ...(note ? { note } : {}),
          ...(form ? { form } : {}),
          ...(use.confirm && arg !== use.confirm ? { blocked: { key: "plugin.typeToConfirm", args: { word: use.confirm } } } : {}),
          ...(pv.danger || use.confirm ? { danger: true } : {}),
          effect: { plugin: { plugin, op: use.op, payload: use.payload, at: obj } },
        };
      },
    });
  }

  const topo = d.topology;
  const mapAct = topo ? { map: { kind: MapKind.Topology, anchor: rootId } } : null;
  const topoTitle = topo ? text(topo.title, "its map") : null;

  // The screens its places open, by route.
  const screens = new Map<string, string>();

  // The nodes.
  const nodes: Omit<Node, "home">[] = [];
  let root: Omit<Node, "home"> | null = null;
  for (const [id, p] of declared) {
    const where = id === "" ? "its root" : `the place "${id}"`;
    const nid = nodeId(id);
    if (p.screen !== undefined) {
      if (typeof p.screen !== "string") fail(`a screen for ${where} that is not a route`);
      if (p.map) fail(`${where} as a map row that opens a screen`);
      if (screens.has(p.screen)) fail(`the screen "${p.screen}" opened by two places`);
      screens.set(p.screen, nid);
    }
    const home = homes.get(id)!;
    const kids: Entry[] | null = p.map
      ? null
      : (p.kids ?? []).map((k): Entry => {
          switch (k.type) {
            case DeclaredKidType.Place:
              return { id: placeNode(k.id, `a row of ${where}`), ...(k.sub ? { sub: text(k.sub, `a row of ${where}`) } : {}) };
            case DeclaredKidType.Item:
              if (!k.id) fail(`a row of ${where} pointing at no item`);
              return { id: `item:${k.id}`, ...(k.sub ? { sub: text(k.sub, `a row of ${where}`) } : {}) };
            case DeclaredKidType.Heading:
              return { heading: text(k.title, `a caption of ${where}`) };
            case DeclaredKidType.Gap:
              return { gap: true };
            default:
              return fail(`a row of ${where} of an unknown kind "${(k as { type: string }).type}"`);
          }
        });
    if (p.map && p.kids?.length) fail(`${where} as a map row with rows of its own`);
    if (p.map && !mapAct) fail(`${where} as a map row and no map`);
    const hue = p.hue === undefined ? undefined : isEnumValue(Hue, p.hue) ? p.hue : fail(`the hue "${p.hue}" for ${where}`);
    if (p.find && !GROUPS.has(p.find.group)) fail(`the search group "${p.find.group}" for ${where}`);
    const name = text(p.title, where);
    const node: Omit<Node, "home"> = {
      id: nid,
      kind: NodeKind.Plugin,
      slug: slugOf(p),
      name,
      ...(p.row_title ? { rowName: text(p.row_title, where) } : {}),
      icon: icon(p.icon, where),
      ...(p.subtitle ? { sub: text(p.subtitle, where) } : {}),
      ...(typeof p.count === "number" ? { count: p.count } : {}),
      level: level(p.level, where),
      ...(p.why ? { why: text(p.why, where) } : {}),
      ...(p.short ? { short: text(p.short, where) } : {}),
      ...(p.mono ? { mono: true } : {}),
      ...(p.sub_mono ? { subMono: true } : {}),
      ...(p.wide ? { wide: true } : {}),
      ...(hue ? { hue } : {}),
      ...(kids ? { kids: () => kids } : {}),
      ...(p.map ? { map: { kind: MapKind.Topology as const, anchor: rootId } } : {}),
      ...(p.find
        ? { result: { group: p.find.group, kind: p.find.kind, orgId: null, place: home.slice(0, -1), haystack: p.find.words.toLowerCase() } }
        : {}),
    };
    node.doc = docOf(p, node, home);
    if (id === "") root = node;
    else nodes.push(node);
  }

  function docOf(p: DeclaredPlace, node: Omit<Node, "home">, home: string[]): (dir: Directory) => DocSpec {
    const where = p.id === "" ? "its root's page" : `the page of "${p.id}"`;
    const pg = p.page;
    const verbAction = (id: string): Action => {
      const v = verbs.get(id) ?? fail(`${where} offering the verb "${id}", which it does not declare`);
      if (!usesOf.get(id)!.has(node.id)) fail(`${where} offering the verb "${id}", which does not apply there`);
      return { icon: v.icon ?? "verb", label: v.name, act: { verb: id } };
    };
    // A place that opens a screen offers it: as the main action where the
    // page names none, else first beside it.
    const open: Action | undefined = p.screen === undefined ? undefined : { icon: "window", label: { key: "plugin.openScreen" }, act: { screen: { node: node.id, plugin, route: p.screen } } };
    const primary = pg?.primary ? verbAction(pg.primary) : open;
    const more = [
      ...(pg?.primary && open ? [open] : []),
      ...(pg?.more ?? []).map(verbAction),
      ...(pg?.map ? [mapAct && topoTitle ? { icon: "map", label: topoTitle, act: mapAct } : fail(`${where} offering a map and no map`)] : []),
    ];
    const what = opt(pg?.what, where) ?? node.sub;
    const state = mark(pg?.state, where) ?? (node.why ? { level: node.level, text: node.why } : undefined);
    const note = opt(pg?.note, where);
    // The sections are read once; a reference's name is the graph's.
    const sections = (pg?.sections ?? []).map((s) => ({
      title: text(s.title, where),
      count: s.count,
      blocks: s.blocks.map((b) => block(b, where)),
    }));
    return (dir: Directory): DocSpec => ({
      hero: {
        lead: { tile: LeadTile.Node, id: node.id },
        title: node.name,
        ...(node.mono ? { mono: true } : {}),
        place: home.slice(0, -1),
        ...(what ? { what } : {}),
        ...(state ? { state } : {}),
        ...(primary ? { primary } : {}),
        ...(more.length ? { more } : {}),
      },
      sections: sections.map(
        (s): Section => ({ title: s.title, ...(s.count !== undefined ? { count: s.count } : {}), blocks: s.blocks.map((b) => b(dir)) }),
      ),
      ...(note ? { note } : {}),
      ...(node.wide ? { wide: true } : {}),
    });
  }

  function block(b: DeclaredBlock, where: string): (dir: Directory) => Block {
    switch (b.type) {
      case DeclaredBlockType.Field: {
        const out: Block = { field: text(b.label, where), value: text(b.value, where), ...(b.mono ? { mono: true } : {}), ...(b.mark ? { mark: mark(b.mark, where)! } : {}) };
        return () => out;
      }
      case DeclaredBlockType.Ref: {
        const id = target(b.to, `a line of ${where}`);
        const title = opt(b.title, where);
        const context = opt(b.context, where);
        const m = mark(b.mark, where);
        return (dir) => ({ ref: id, lead: { tile: LeadTile.Node, id }, title: title ?? dir.node(id).name, ...(b.mono ? { mono: true } : {}), ...(context ? { context } : {}), ...(m ? { mark: m } : {}) });
      }
      case DeclaredBlockType.Finding: {
        const out: Block = {
          sig: level(b.level, where),
          title: text(b.title, where),
          ...(b.sub ? { sub: text(b.sub, where) } : {}),
          ...(b.to ? { go: { go: target(b.to, `a finding of ${where}`) } } : {}),
        };
        return () => out;
      }
      case DeclaredBlockType.Para: {
        const out: Block = { para: text(b.text, where) };
        return () => out;
      }
      case DeclaredBlockType.MapDoor: {
        if (!mapAct) return fail(`${where} with a door to a map it does not declare`);
        const out: Block = { mapdoor: mapAct.map, title: text(b.title, where), sub: text(b.sub, where) };
        return () => out;
      }
      default:
        return fail(`${where} with a block of an unknown kind "${(b as { type: string }).type}"`);
    }
  }

  const signals: Record<string, ExtraSignal> = {};
  for (const m of d.marks ?? []) {
    const where = `its finding about the item "${m.item}"`;
    if (!m.item) fail("a finding about no item");
    if (signals[m.item]) fail(`two findings about the item "${m.item}"`);
    signals[m.item] = { level: level(m.level, where), why: text(m.why, where), short: text(m.short, where) };
  }
  const links: Link[] = (d.lines ?? []).map((l) => {
    const where = `a line from "${l.from}"`;
    const lv = loud(l.level, where);
    return { from: placeNode(l.from, where), to: target({ item: l.item }, where), kind: edge(l.kind, where), ...(lv ? { level: lv } : {}), words: text(l.words, where), short: text(l.short, where) };
  });

  let topology: ((dir: Directory) => MapModel) | undefined;
  if (topo) {
    const lanes = topo.lanes.map((x) => text(x, "its map's lanes"));
    if (!Number.isInteger(topo.pivot) || topo.pivot < 0 || topo.pivot >= Math.max(lanes.length, 1)) fail(`its map's pivot ${topo.pivot} outside its lanes`);
    const points = topo.points.map((p) => {
      if (!Number.isInteger(p.lane) || p.lane < 0 || p.lane >= lanes.length) fail(`a point of its map in lane ${p.lane} of ${lanes.length}`);
      return { id: target(p.at, "a point of its map"), lane: p.lane };
    });
    const on = new Set(points.map((p) => p.id));
    if (on.size !== points.length) fail("a point twice on its map");
    const onMap = (t: DeclaredTarget, where: string) => {
      const id = target(t, where);
      if (!on.has(id)) fail(`${where} at "${id}", which is not on the map`);
      return id;
    };
    const edges = topo.edges.map((e) => {
      const where = "a line of its map";
      const lv = loud(e.level, where);
      return { a: onMap(e.a, where), b: onMap(e.b, where), kind: edge(e.kind, where), ...(lv ? { level: lv } : {}), words: text(e.words, where), ...(e.chip ? { chip: true } : {}) };
    });
    const findings = (topo.findings ?? []).map((f) => ({ level: level(f.level, "a finding of its map"), text: text(f.text, "a finding of its map"), focus: onMap(f.focus, "a finding of its map") }));
    const legend = (topo.legend ?? []).map((x) => {
      const lv = loud(x.level, "its map's legend");
      return { kind: edge(x.kind, "its map's legend"), ...(lv ? { level: lv } : {}), text: text(x.text, "its map's legend") };
    });
    const place = text(topo.place, "its map");
    topology = (dir) => ({ nodes: points.map((p) => pointOf(dir, p.id, p.lane)), edges, lanes, pivot: topo.pivot, title: topoTitle!, place, findings, legend });
  }

  return {
    id: plugin,
    root: root!,
    nodes,
    homes: Object.fromEntries([...homes].filter(([id]) => id !== "").map(([id, h]) => [nodeId(id), h])),
    ...(Object.keys(signals).length ? { signals } : {}),
    ...(links.length ? { links } : {}),
    ...(topology ? { topology } : {}),
    ...(verbs.size ? { verbs: [...verbs.values()] } : {}),
    ...(words ? { words } : {}),
    ...(screens.size ? { screens: Object.fromEntries(screens) } : {}),
  };
}

/// A plugin that did not answer, or answered what does not hold together:
/// its place stands, loud, with the reason, so that one plugin neither takes
/// the window down nor vanishes without a word.
export function failedContribution(plugin: string, title: string, icon: string, reason: string): Contribution {
  const rootId = pluginRootId(plugin);
  const why: Text = { key: "plugin.failed", args: { reason } };
  const name: Text = { raw: title };
  return {
    id: plugin,
    root: {
      id: rootId,
      kind: NodeKind.Plugin,
      slug: slugify(plugin) || "plugin",
      name,
      icon,
      level: Level.Warning,
      why,
      short: { key: "plugin.failedShort" },
      doc: () => ({ hero: { lead: { tile: LeadTile.Node, id: rootId }, title: name, place: [], state: { level: Level.Warning, text: why } }, sections: [] }),
    },
    nodes: [],
    homes: {},
  };
}

