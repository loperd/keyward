// The line's language. A path is a list of segments — a step to a node, or a
// filter (tokens and words) whose results become a column. The same state is
// written two ways: as syntax in the URL and while typing (`org:acme state:
// critical > rotate`), and as crumbs of human names everywhere else. Pure.
import { currentLang, t, text, type Key, type Text } from "../i18n";
import { Level } from "../model/types";
import { LEVEL_RANK } from "../model/signals";
import { isStep, type Directory, type Entry, MapKind, type Node, ResultGroup, NodeKind } from "./directory";
import { onMap } from "../map/model";
import type { Preview } from "../verbs/spec";
import { enumParser, isEnumValue } from "../model/enum";

export type Token = { k: TokenKey; v: string };
export type Filter = { tokens: Token[]; words: string[] };
export type Segment = { id: string } | { filter: Filter };
export type MapRef = { kind: MapKind; anchor: string };
export type PathState = { segs: Segment[]; map: MapRef | null; verb: string | null; arg: string };

export const EMPTY: PathState = { segs: [], map: null, verb: null, arg: "" };

/// A filter token's key, the word before the colon (`org:acme`).
export enum TokenKey {
  Org = "org",
  Member = "member",
  State = "state",
  Kind = "kind",
  Host = "host",
  In = "in",
  Item = "item",
  Map = "map",
}
export const TOKEN_KEYS: readonly TokenKey[] = Object.values(TokenKey);
export const parseTokenKey = enumParser(TokenKey, "a filter key");

/// A state a filter asks for; `attention` is everything not healthy.
export const STATES: Record<string, Level[]> = {
  critical: [Level.Critical],
  action: [Level.Action],
  warning: [Level.Warning],
  healthy: [Level.Healthy],
  unknown: [Level.Unknown],
  attention: [Level.Critical, Level.Action, Level.Warning],
};

/// A verb a line can end with: what it is called and what it applies to.
export type Verb = {
  id: string;
  name: Text;
  icon?: string;
  applies: (n: Node | null) => boolean;
  /// What it will do, before it does it; a plugin's verb brings its own.
  preview?: (dir: Directory, obj: string, arg: string) => Preview;
  /// A node it works on, offered when the object does not fit.
  example?: (dir: Directory) => string | null;
  /// Why it does not apply to an object it would otherwise fit (removing
  /// yourself, demoting the last owner): a preview that says so instead of
  /// "does not fit". Not offered there, but explained when typed.
  refuses?: (dir: Directory, obj: string) => Preview | null;
  /// Its argument in words, for the crumb: syntax never shows in a crumb.
  argName?: (dir: Directory, obj: string | null, arg: string) => Text | null;
};

export const isFilter = (s: Segment): s is { filter: Filter } => "filter" in s;
export const objectOf = (segs: Segment[]): string | null => {
  const l = segs[segs.length - 1];
  return l && !isFilter(l) ? l.id : null;
};

const GLOBS = new Map<string, RegExp>();
/// Forgets the patterns typed so far: they are a person's search words, and
/// go when the session closes.
export const forgetGlobs = () => GLOBS.clear();
const glob = (g: string) => {
  let re = GLOBS.get(g);
  if (!re) GLOBS.set(g, (re = new RegExp("^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "i")));
  return re;
};

/// A filter's identity, for the results kept per graph.
const filterKey = (f: Filter) => JSON.stringify([f.tokens.map((x) => [x.k, x.v]), f.words]);
/// How many filters' results a query keeps: the ones typed lately.
const RESULTS_KEPT = 64;

export class Query {
  // A graph never changes after it is built, so what is read from it is kept
  // for the life of the query: a filter's results, a list as a set, a list's
  // words as an index.
  private readonly resultsMemo = new Map<string, readonly string[]>();
  private readonly listSets = new WeakMap<readonly string[], Set<string>>();
  private readonly listWords = new WeakMap<readonly string[], { lang: string; words: Map<string, string> }>();
  private readonly groupedMemo = new WeakMap<readonly string[], readonly Entry[]>();

  constructor(
    readonly dir: Directory,
    readonly verbs: Verb[],
  ) {}

  /// Whether a list (one this query or its graph handed out) holds an id.
  inList(list: readonly string[], id: string): boolean {
    let set = this.listSets.get(list);
    if (!set) this.listSets.set(list, (set = new Set(list)));
    return set.has(id);
  }

  /// Does a node pass a filter.
  matches(id: string, f: Filter): boolean {
    const n = this.dir.node(id);
    const r = n.result;
    if (!r) return false;
    for (const tk of f.tokens) {
      if (tk.k === TokenKey.State && !(STATES[tk.v] ?? []).includes(n.level)) return false;
      if (tk.k === TokenKey.Kind && r.kind !== tk.v && !(tk.v === "ssh" && r.group === ResultGroup.Hosts)) return false;
      if (tk.k === TokenKey.Host && !(r.group === ResultGroup.Hosts && glob(tk.v).test(r.haystack.split(" ")[0] ?? ""))) return false;
      if (tk.k === TokenKey.Org && this.dir.bySlugOrNull(tk.v) !== (r.orgId ? `org:${r.orgId}` : null)) return false;
      if (tk.k === TokenKey.In && !n.home.includes(this.dir.bySlugOrNull(tk.v) ?? "\0")) return false;
    }
    return f.words.every((w) => r.haystack.includes(w.toLowerCase()));
  }

  /// A filter's results under a scope, the most serious first.
  /// Kept per graph; frozen, as everyone reading it shares it.
  results(scope: string, f: Filter): readonly string[] {
    const k = `${scope}\0${filterKey(f)}`;
    const hit = this.resultsMemo.get(k);
    if (hit) return hit;
    const found = this.dir
      .universe(scope)
      .filter((id) => this.matches(id, f))
      .sort((a, b) => LEVEL_RANK[this.dir.node(a).level] - LEVEL_RANK[this.dir.node(b).level]);
    if (this.resultsMemo.size >= RESULTS_KEPT) this.resultsMemo.delete(this.resultsMemo.keys().next().value!);
    const out = Object.freeze(found);
    this.resultsMemo.set(k, out);
    return out;
  }

  /// A filter's results grouped by what was found, under a caption each.
  grouped(ids: readonly string[]): readonly Entry[] {
    let out = this.groupedMemo.get(ids);
    if (!out) {
      const groups = [ResultGroup.Items, ResultGroup.Hosts, ResultGroup.Members, ResultGroup.Clusters];
      const by = new Map<string, string[]>(groups.map((g) => [g, []]));
      for (const id of ids) by.get(this.dir.node(id).result?.group ?? "")?.push(id);
      out = Object.freeze(
        groups.flatMap((g) => {
          const xs = by.get(g)!;
          return xs.length ? [{ heading: { key: `group.${g}` as Key }, count: xs.length }, ...xs.map((id) => ({ id }))] : [];
        }),
      );
      this.groupedMemo.set(ids, out);
    }
    return out;
  }

  /// The list that follows segments: the last step's kids, or a filter's
  /// results over the step before it.
  listAfter(segs: Segment[]): readonly string[] {
    const last = segs[segs.length - 1];
    if (!last) return this.dir.kidIds("root");
    if (isFilter(last)) {
      const before = segs[segs.length - 2];
      return this.results(before && !isFilter(before) ? before.id : "root", last.filter);
    }
    return this.dir.kidIds(last.id);
  }

  /// A word as a step: among the next list first (so "участники" inside one
  /// organisation is its own members), anywhere in the graph after.
  private stepOf(word: string, segs: Segment[]): string | null {
    const next = this.listAfter(segs);
    const w = word.toLowerCase();
    // The first of the list whose slug or name (in the language of the
    // moment) is the word: an index per list and language.
    const lang = currentLang();
    let idx = this.listWords.get(next);
    if (!idx || idx.lang !== lang) {
      const words = new Map<string, string>();
      for (const id of next) {
        const n = this.dir.node(id);
        if (!words.has(n.slug)) words.set(n.slug, id);
        const name = text(n.name).toLowerCase();
        if (!words.has(name)) words.set(name, id);
      }
      this.listWords.set(next, (idx = { lang, words }));
    }
    return idx.words.get(w) ?? this.dir.stepOf(w);
  }

  /// A token naming one node becomes a step; the rest stay a filter.
  private resolve(k: TokenKey, v: string): string | null {
    if (k === TokenKey.Org || k === TokenKey.In || k === TokenKey.Item || k === TokenKey.Member) {
      const id = this.dir.bySlugOrNull(v);
      if (!id) return null;
      const n = this.dir.node(id);
      const want = { [TokenKey.Org]: NodeKind.Org, [TokenKey.In]: null, [TokenKey.Item]: NodeKind.Item, [TokenKey.Member]: NodeKind.Member }[k];
      if (want && n.kind !== want) return null;
      if (k === TokenKey.In && ![NodeKind.Folder, NodeKind.Collection].includes(n.kind)) return null;
      return id;
    }
    if (k === TokenKey.Host && !v.includes("*")) {
      const id = this.dir.bySlugOrNull(v);
      return id && this.dir.node(id).result?.group === ResultGroup.Hosts ? id : null;
    }
    return null;
  }

  /// The map a node opens, if it has one.
  mapFor(id: string | null): MapRef | null {
    if (!id) return null;
    const n = this.dir.node(id);
    if (n.map) return n.map;
    if (n.kind === NodeKind.Item) return { kind: MapKind.Relations, anchor: id };
    const org = n.home.find((x) => x.startsWith("org:") && !x.includes("/"));
    if (org && this.dir.has(`${org}/access`)) return { kind: MapKind.Access, anchor: org };
    const plugin = n.home[0] && this.dir.contributions.find((c) => c.root.id === n.home[0] && c.topology);
    return plugin ? { kind: MapKind.Topology, anchor: plugin.root.id } : null;
  }

  /// Text → state. A step not in the next list re-roots at its home.
  compile(str: string): PathState {
    const gt = str.indexOf(">");
    const left = gt >= 0 ? str.slice(0, gt) : str;
    const right = gt >= 0 ? str.slice(gt + 1).trim().toLowerCase() : null;
    // The argument keeps its case: a collection's new name is a name.
    const rawRight = gt >= 0 ? str.slice(gt + 1).trim() : "";
    let segs: Segment[] = [];
    let map: MapRef | null = null;
    const step = (id: string) => {
      if (this.inList(this.listAfter(segs), id)) segs.push({ id });
      else segs = this.dir.node(id).home.map((x) => ({ id: x }));
    };
    const filter = (): Filter => {
      const l = segs[segs.length - 1];
      if (l && isFilter(l)) return l.filter;
      const f: Filter = { tokens: [], words: [] };
      segs.push({ filter: f });
      return f;
    };
    for (const raw of left.replace(/[›/]/g, " ").split(/\s+/).filter(Boolean)) {
      // boundary: a typed `key:value` whose key is a filter key becomes a
      // token; any other word stays a search word.
      const m = /^([a-z]+):(.+)$/.exec(raw.toLowerCase());
      if (m && isEnumValue(TokenKey, m[1])) {
        const k: TokenKey = m[1];
        const v = m[2]!;
        if (k === TokenKey.Map) {
          map = this.mapToken(v, segs, (s) => (segs = s));
          continue;
        }
        const last = segs[segs.length - 1];
        const id = this.resolve(k, v);
        if (id && !(k === TokenKey.Org && last && isFilter(last))) step(id);
        else filter().tokens.push({ k, v });
        continue;
      }
      const id = this.stepOf(raw, segs);
      if (id) step(id);
      else filter().words.push(raw.toLowerCase());
    }
    let verb: string | null = null;
    let arg = "";
    if (right !== null) {
      const v = this.verbs.filter((x) => right.startsWith(x.id)).sort((a, b) => b.id.length - a.id.length)[0];
      verb = v ? v.id : right;
      arg = v ? rawRight.slice(v.id.length).trim() : "";
    }
    // "> map" needs no preview: the map is its own.
    if (verb === "map") {
      map = this.mapFor(objectOf(segs));
      verb = null;
      arg = "";
    }
    const o = objectOf(segs);
    const on = o ? this.dir.node(o) : null;
    // A map stays only while the object is one of its points.
    if (on?.map) map = on.map;
    else if (map && !onMap(this.dir, map, o)) map = null;
    if (verb !== null) map = null;
    return { segs, map, verb, arg };
  }

  private mapToken(v: string, segs: Segment[], set: (s: Segment[]) => void): MapRef | null {
    const o = objectOf(segs);
    if (v === MapKind.Relations && o) return { kind: MapKind.Relations, anchor: o };
    const id = this.dir.bySlugOrNull(v);
    if (!id) return null;
    const n = this.dir.node(id);
    // A map token keeps the path where it stands while its object is a
    // point of the map, and goes to the map's own place otherwise.
    if (n.map) {
      if (!onMap(this.dir, n.map, o)) set(n.home.map((x) => ({ id: x })));
      return n.map;
    }
    if (n.kind === NodeKind.Item) {
      const m: MapRef = { kind: MapKind.Relations, anchor: id };
      if (!onMap(this.dir, m, o)) set(n.home.map((x) => ({ id: x })));
      return m;
    }
    return this.mapFor(id);
  }

  /// State → text, as the URL keeps it.
  serialize(st: PathState): string {
    const seg = (s: Segment) =>
      isFilter(s) ? [...s.filter.tokens.map((x) => `${x.k}:${x.v}`), ...s.filter.words].join(" ") : this.dir.node(s.id).slug;
    let s = st.segs.map(seg).join(" › ");
    const o = objectOf(st.segs);
    const own = o ? this.dir.node(o).map : null;
    if (st.map && !own) s += (s ? " " : "") + (st.map.kind === MapKind.Relations ? `map:${this.dir.node(st.map.anchor).slug}` : "> map");
    if (st.verb !== null) s += (s ? " " : "") + `> ${st.verb}${st.arg ? ` ${st.arg}` : ""}`;
    return s;
  }

  nodeLabel(id: string): string {
    return nodeName(this.dir.node(id));
  }
  /// Is a node a point of a map.
  mapHas(m: MapRef | null, id: string | null): boolean {
    return onMap(this.dir, m, id);
  }

  /// A filter token's human name.
  tokenName(x: Token): string {
    switch (x.k) {
      case TokenKey.State:
        return `${t("filter.state")}: ${x.v in STATES ? t(x.v === "attention" ? "level.attention" : (`level.${x.v}` as Key)) : x.v}`;
      case TokenKey.Kind:
        return `${t("filter.kind")}: ${KIND_KEYS[x.v] ? t(KIND_KEYS[x.v]!) : x.v}`;
      case TokenKey.Host:
        return `${t("filter.host")}: ${x.v.replace(/^\*\./, "")}`;
      case TokenKey.Org:
      case TokenKey.In:
      case TokenKey.Member:
      case TokenKey.Item: {
        const id = this.dir.bySlugOrNull(x.v);
        const label = { org: "filter.org", in: "filter.in", member: "filter.member", item: "filter.item" }[x.k] as Key;
        return `${t(label)}: ${id ? nodeName(this.dir.node(id)) : x.v}`;
      }
      default:
        return `${x.k}: ${x.v}`;
    }
  }
  filterName(f: Filter): string {
    return [...f.tokens.map((x) => this.tokenName(x)), ...(f.words.length ? [`${t("filter.words")}: ${f.words.join(" ")}`] : [])].join(", ");
  }
  verbName(id: string): string {
    const v = this.verbs.find((x) => x.id === id);
    return v ? text(v.name) : `${t("verb.unknown")}: ${id}`;
  }
  /// The verbs that apply where the path ends.
  verbsFor(st: PathState): Verb[] {
    const o = objectOf(st.segs);
    const n = o ? this.dir.node(o) : null;
    return this.verbs.filter((v) => v.applies(n));
  }
}

const KIND_KEYS: Record<string, Key> = {
  login: "kind.login",
  card: "kind.card",
  identity: "kind.identity",
  secure_note: "kind.secure_note",
  note: "kind.secure_note",
  ssh_key: "kind.ssh_key",
  ssh: "kind.ssh_key",
  host: "kind.host",
  member: "kind.member",
  cluster: "kind.cluster",
};

export const nodeName = (n: Node): string => text(n.name);

/// One crumb kind: an icon and a human name. Places, filters, results, maps
/// and actions all read the same way; syntax never shows in a crumb.
/// Where a crumb cuts the line: a map or a verb, past the segments.
export enum CrumbCut {
  Map = "map",
  Verb = "verb",
}
export type Crumb = { key: string; icon: string; level?: Level; name: string; title?: string; cut: number | CrumbCut };

export function crumbs(q: Query, st: PathState): Crumb[] {
  const out: Crumb[] = [{ key: "root", icon: "vault", name: t("root"), cut: 0 }];
  st.segs.forEach((s, j) => {
    if (isFilter(s)) {
      const lone = s.filter.tokens.length === 1 && s.filter.words.length === 0 ? s.filter.tokens[0]! : null;
      const state = lone?.k === TokenKey.State ? STATES[lone.v] : undefined;
      out.push({
        key: `f:${j}:${q.filterName(s.filter)}`,
        icon: state ? "state" : s.filter.tokens.length ? "filter" : "search",
        ...(state && state.length === 1 ? { level: state[0] } : state ? { level: Level.Action } : {}),
        name: q.filterName(s.filter),
        cut: j + 1,
      });
      return;
    }
    const n = q.dir.node(s.id);
    if (n.map) return;
    out.push({ key: `p:${s.id}`, icon: n.icon, name: nodeName(n), cut: j + 1 });
  });
  if (st.map) {
    const name = t(MAP_KEYS[st.map.kind]);
    out.push({
      key: `m:${st.map.kind}:${st.map.anchor}`,
      icon: "map",
      name,
      ...(st.map.kind === MapKind.Relations ? { title: `${name} · ${nodeName(q.dir.node(st.map.anchor))}` } : {}),
      cut: CrumbCut.Map,
    });
  }
  if (st.verb !== null) {
    const v = q.verbs.find((x) => x.id === st.verb);
    const said = st.arg && v?.argName ? v.argName(q.dir, objectOf(st.segs), st.arg) : null;
    const arg = said ? text(said) : st.arg;
    out.push({ key: `v:${st.verb}`, icon: "verb", name: q.verbName(st.verb) + (arg ? ` · ${arg}` : ""), cut: CrumbCut.Verb });
  }
  return out;
}

export const MAP_KEYS: Record<MapKind, Key> = { [MapKind.Relations]: "map.relations", [MapKind.Access]: "map.access", [MapKind.Topology]: "map.topology" };

/// A column of the path: a node's kids, or a filter's results.
export enum ColumnType {
  Kids = "kids",
  Results = "results",
}
export type Column = { type: ColumnType.Kids; parent: string; at: number; sel: string | null } | { type: ColumnType.Results; scope: string; filter: Filter; at: number; sel: string | null };

export function columns(q: Query, segs: Segment[], map: MapRef | null): Column[] {
  const cols: Column[] = [];
  let scope = "root";
  let i = 0;
  for (;;) {
    const s = segs[i];
    let col: Column;
    if (s && isFilter(s)) {
      i++;
      const nx = segs[i];
      col = { type: ColumnType.Results, scope, filter: s.filter, at: i, sel: nx && !isFilter(nx) ? nx.id : null };
    } else if (q.dir.node(scope).kids) {
      const nx = segs[i];
      col = { type: ColumnType.Kids, parent: scope, at: i, sel: nx && !isFilter(nx) ? nx.id : null };
    } else break;
    cols.push(col);
    if (!col.sel) break;
    // With a map open, the list holding the selection is the last.
    if (map && i === segs.length - 1) break;
    scope = col.sel;
    i++;
  }
  return cols;
}

/// Which columns stay open: the last two of the path — one with a map, in a
/// narrow window, or when two do not fit beside the inspector. Every earlier
/// column is a spine; a spine is never between open ones, because opening a
/// spine shortens the path back to it (`PathStore.expand`), so it becomes one
/// of the last two.
export function fold(n: number, opts: { map: boolean; narrow: boolean; fits: (open: number) => boolean; shown?: number | null }): boolean[] {
  let max = opts.map || opts.narrow ? 1 : 2;
  while (max > 1 && !opts.fits(max)) max--;
  // The open pair stays together: by default the last columns; a column
  // unfolded from a spine pulls the pair onto itself, from either side.
  let start = Math.max(0, n - max);
  const want = opts.shown;
  if (want !== null && want !== undefined && want >= 0 && want < n) {
    if (want < start) start = want;
    else if (want >= start + max) start = want - max + 1;
  }
  return Array.from({ length: n }, (_, i) => i >= start && i < start + max);
}

/// The shape of the answer: a verb is a preview, a map is a map, a filter
/// with nothing chosen is a calm list, anything else is the object's document.
export enum AnswerKind {
  Verb = "verb",
  Map = "map",
  List = "list",
  Document = "document",
}
export type Answer = { kind: AnswerKind.Verb } | { kind: AnswerKind.Map } | { kind: AnswerKind.List; column: Column } | { kind: AnswerKind.Document; id: string | null };
export function answerOf(st: PathState, cols: Column[]): Answer {
  if (st.verb !== null) return { kind: AnswerKind.Verb };
  if (st.map) return { kind: AnswerKind.Map };
  const last = cols[cols.length - 1];
  if (last && last.type === ColumnType.Results && !last.sel) return { kind: AnswerKind.List, column: last };
  return { kind: AnswerKind.Document, id: objectOf(st.segs) };
}

/// A column's rows, a results column grouped by what was found.
/// Kept per graph and column, and frozen.
export function rows(q: Query, col: Column): readonly Entry[] {
  if (col.type === ColumnType.Kids) return q.dir.kids(col.parent);
  return q.grouped(q.results(col.scope, col.filter));
}

export { isStep };
