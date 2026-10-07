// The graph the path walks: every place a person can step to — the vault,
// an owner, a folder, an organisation and its sections, a collection, an
// item, a member, and what plugins add (hosts, clusters). Built from the
// catalogue each time it changes; pure, no React, no backend.
import { text, textsOf, type Key, type Text, type Words } from "../i18n";
import { worst, type Signal } from "../model/signals";
import { duplicatesOf, itemState, itemStateOf, memberState, settledSignals, type ExtraSignal } from "../model/reasons";
import { type Catalog, type Collection, type Item, ItemKind, Level, type Member, type Org, Permission, type Policy, PolicyType, MemberStatus } from "../model/types";
import { type DocSpec, Hue } from "../doc/spec";
import type { Link, MapModel } from "../map/types";
import type { Place } from "./places";
import type { Verb } from "./query";
import { enumParser } from "../model/enum";
import { PAGE_ICON, PAGE_NAME, pageDoc, pageId, pageSub, SETTINGS_ID, type SettingsPage, settingsDoc } from "../settings/pages";

export enum NodeKind {
  Root = "root",
  All = "all",
  Personal = "personal",
  Folder = "folder",
  Org = "org",
  Section = "section",
  Collection = "collection",
  Item = "item",
  Member = "member",
  Trash = "trash",
  Plugin = "plugin",
  Settings = "settings",
  SettingsPage = "settingsPage",
}
export enum MapKind {
  Relations = "relations",
  Access = "access",
  Topology = "topology",
}
export const parseMapKind = enumParser(MapKind, "a map kind");
/// What a result is, for grouping a results column.
export enum ResultGroup {
  Items = "items",
  Hosts = "hosts",
  Members = "members",
  Clusters = "clusters",
}
export const parseResultGroup = enumParser(ResultGroup, "a result group");
/// What a result is, in the word a filter's `kind:` matches: an item's kind
/// (`ItemKind`) or one of these. A plugin's result may bring a word of its
/// own, so a result's kind is kept as a word.
export enum ResultKind {
  Member = "member",
  Host = "host",
  Cluster = "cluster",
}

/// A row of a column: a step, a caption between groups, a breath between
/// kinds of rows, or a saved place that runs its query.
export type Step = { id: string; sub?: Text; off?: boolean };
export type Entry = Step | { heading: Text; count?: number } | { gap: true } | { place: string };

export type Node = {
  id: string;
  kind: NodeKind;
  /// The URL's word for the step; unique in the graph.
  slug: string;
  name: Text;
  /// The shorter name a row shows where its column already says the rest
  /// (`db-1` under Hosts for `db-1.prod.demo.example`).
  rowName?: Text;
  icon: string;
  /// The quiet second line of its row.
  sub?: Text;
  /// How many it holds, on the row's right edge where it has no second line.
  count?: number;
  level: Level;
  /// Why it stands at its level, in words: a mark's tooltip, a hero's state.
  why?: Text;
  /// The same in a word, for a relation's mark.
  short?: Text;
  /// The canonical path from the root to it, itself included.
  home: string[];
  /// Steps reachable from it; absent on a leaf.
  kids?: () => Entry[];
  /// A row that is itself a map of its anchor (Acme → Access map).
  map?: { kind: MapKind; anchor: string };
  /// A thing a filter can find; `place` is the path of nodes it lives under.
  result?: { group: ResultGroup; kind: string; orgId: string | null; place: string[]; haystack: string };
  item?: Item;
  /// How many other copies of the item's record the vault holds: what
  /// `> merge` is offered on.
  copies?: number;
  member?: Member;
  policy?: Policy;
  /// The organisation it lives in: what a verb asks of `can` there.
  org?: Org;
  /// A wide column: its rows carry a second line worth reading.
  wide?: boolean;
  /// Its name (and its second line) is a machine's word: a host, a cluster.
  mono?: boolean;
  subMono?: boolean;
  /// The tile's colour for an organisation or a plugin's section.
  hue?: Hue;
  /// A plugin's page for it, in the core's vocabulary.
  doc?: (dir: Directory) => DocSpec;
};

/// What a plugin adds under the root: its own nodes with their kids and
/// homes, its findings about items, its lines to items, its map and verbs.
export type Contribution = {
  id: string;
  root: Omit<Node, "home">;
  nodes: Omit<Node, "home">[];
  homes: Record<string, string[]>;
  signals?: Record<string, ExtraSignal>;
  links?: Link[];
  topology?: (dir: Directory) => MapModel;
  verbs?: Verb[];
  /// Its words, registered under its id.
  words?: Words;
};

export const isStep = (e: Entry): e is Step => "id" in e;

const ITEM_ICON: Record<ItemKind, string> = { [ItemKind.Login]: "login", [ItemKind.Card]: "card", [ItemKind.Identity]: "identity", [ItemKind.SecureNote]: "note", [ItemKind.SshKey]: "key" };
const ORG_HUES: Hue[] = [Hue.Orange, Hue.Cyan, Hue.Amber, Hue.Mint, Hue.Sky];

/// `GitLab — platform` → `gitlab-platform`: lowercase letters of any script,
/// digits and single dashes.
export function slugify(s: string): string {
  // Plain ASCII, the usual name, is read char by char: lowercasing and NFKC
  // leave it as it is, and its letters and digits are a-z and 0-9.
  if (ASCII.test(s)) {
    let out = "";
    let dash = false;
    for (let i = 0; i < s.length; i++) {
      let c = s.charCodeAt(i);
      if (c >= 65 && c <= 90) c += 32;
      if ((c >= 97 && c <= 122) || (c >= 48 && c <= 57)) {
        if (dash && out) out += "-";
        dash = false;
        out += String.fromCharCode(c);
      } else dash = true;
    }
    return out;
  }
  return s
    .toLowerCase()
    .normalize("NFKC")
    .replace(/[^\p{L}\p{N}]+/gu, "-")
    .replace(/^-+|-+$/g, "");
}

const ASCII = /^[\x00-\x7f]*$/;

export const memberLevel = (m: Member): Level => memberState(m).level;
const LOUD: Level[] = [Level.Critical, Level.Action, Level.Warning];
export const isLoud = (l: Level) => LOUD.includes(l);

/// A policy's level: a rule that is off where it protects, or set looser
/// than advised, asks for attention.
export function policyLevel(p: Policy): Level {
  if (p.type === PolicyType.TwoFactor && !p.enabled) return Level.Action;
  if (p.type === PolicyType.VaultTimeout && p.enabled && typeof p.data.minutes === "number" && p.data.minutes > 60) return Level.Warning;
  return Level.Healthy;
}

/// `settings`: the settings' pages the app offers, in their order; none, no
/// Settings on the path (the web app).
export type DirectoryOptions = { places?: Place[]; now?: Date; settings?: SettingsPage[] };

export class Directory {
  private readonly nodes = new Map<string, Node>();
  private readonly bySlug = new Map<string, string>();
  /// Words a person may type for a step, in every language: the slug and the
  /// step's name.
  private readonly aliases = new Map<string, string>();
  private readonly placeMap = new Map<string, Place>();
  private readonly slugNext = new Map<string, number>();
  private slugMemo: Map<string, string> | null = null;
  // Built once per graph, lazily: a graph never changes after it is built,
  // and a node's kids are a pure function of the catalogue it was built from.
  private readonly kidsMemo = new Map<string, readonly Entry[]>();
  private readonly kidIdsMemo = new Map<string, readonly string[]>();
  private readonly universeMemo = new Map<string, readonly string[]>();
  private readonly kindMemo = new Map<NodeKind, readonly Node[]>();
  private readonly searchMemo = new Map<string, readonly string[]>();
  private nodeList: readonly Node[] | null = null;
  private collectionsOf: Map<string, Collection[]> | null = null;
  readonly now: Date;
  readonly places: Place[];
  readonly settings: SettingsPage[];

  constructor(
    readonly catalog: Catalog,
    readonly contributions: Contribution[] = [],
    opts: DirectoryOptions = {},
  ) {
    this.now = opts.now ?? new Date();
    this.places = opts.places ?? [];
    this.settings = opts.settings ?? [];
    for (const p of this.places) {
      if (this.placeMap.has(p.id)) throw new Error(`duplicate place "${p.id}"`);
      this.placeMap.set(p.id, p);
    }
    this.slugMemo = new Map();
    this.build();
    this.slugMemo = null;
  }

  node(id: string): Node {
    const n = this.nodes.get(id);
    if (!n) throw new Error(`no node "${id}" in the graph`);
    return n;
  }
  has(id: string): boolean {
    return this.nodes.has(id);
  }
  all(): Node[] {
    return [...this.nodes.values()];
  }
  /// Every node in the order it was added, without a copy: what a search
  /// over the whole graph walks.
  list(): readonly Node[] {
    return (this.nodeList ??= Object.freeze([...this.nodes.values()]));
  }
  /// The nodes of one kind, in the order they were added.
  ofKind(kind: NodeKind): readonly Node[] {
    let xs = this.kindMemo.get(kind);
    if (!xs) this.kindMemo.set(kind, (xs = Object.freeze(this.list().filter((n) => n.kind === kind))));
    return xs;
  }
  /// A node's name as a person may type it, lowercased, in every language.
  searchTexts(id: string): readonly string[] {
    let xs = this.searchMemo.get(id);
    if (!xs) this.searchMemo.set(id, (xs = Object.freeze(textsOf(this.node(id).name))));
    return xs;
  }
  place(id: string): Place {
    const p = this.placeMap.get(id);
    if (!p) throw new Error(`no place "${id}"`);
    return p;
  }
  /// A node's rows, computed once per graph; frozen, so a caller that would
  /// change them fails at once instead of changing them for everyone.
  kids(id: string): readonly Entry[] {
    let xs = this.kidsMemo.get(id);
    if (!xs) this.kidsMemo.set(id, (xs = Object.freeze(this.node(id).kids?.() ?? [])));
    return xs;
  }
  kidIds(id: string): readonly string[] {
    let xs = this.kidIdsMemo.get(id);
    if (!xs) this.kidIdsMemo.set(id, (xs = Object.freeze(this.kids(id).filter(isStep).map((e) => e.id))));
    return xs;
  }
  /// A step by what a person typed: a slug, or a name in any language.
  stepOf(word: string): string | null {
    const w = word.toLowerCase();
    return this.bySlug.get(w) ?? this.aliases.get(w) ?? null;
  }
  bySlugOrNull(slug: string): string | null {
    return this.bySlug.get(slug) ?? null;
  }
  /// Everything findable under a scope: the results a filter is run over.
  universe(scope: string): readonly string[] {
    let u = this.universeMemo.get(scope);
    if (!u) this.universeMemo.set(scope, (u = Object.freeze(this.walkUniverse(scope))));
    return u;
  }
  private walkUniverse(scope: string): string[] {
    if (scope === "root") return this.list().filter((n) => n.result).map((n) => n.id);
    const out = new Set<string>();
    const seen = new Set<string>();
    const walk = (id: string) => {
      for (const k of this.kidIds(id)) {
        if (seen.has(k)) continue;
        seen.add(k);
        const n = this.node(k);
        if (n.result) out.add(k);
        if (n.kind !== NodeKind.Member) walk(k);
      }
    };
    walk(scope);
    return [...out];
  }
  /// The plugins' lines to items.
  links(): Link[] {
    return this.contributions.flatMap((c) => c.links ?? []);
  }
  /// The map of a plugin's anchor.
  topology(anchor: string): MapModel {
    const c = this.contributions.find((x) => x.root.id === anchor && x.topology);
    if (!c?.topology) throw new Error(`no topology for "${anchor}"`);
    return c.topology(this);
  }
  /// The organisation a node lives in, if any.
  orgOf(id: string): string | null {
    return this.node(id).home.find((x) => x.startsWith("org:") && !x.includes("/")) ?? null;
  }
  /// What a member reaches: each collection of their organisation and the
  /// level they reach it at, `null` where they do not.
  reach(m: Member): { collection: string; perm: Permission | null }[] {
    if (!this.collectionsOf) this.collectionsOf = groupBy(this.catalog.collections, (c) => c.orgId);
    return (this.collectionsOf.get(m.orgId) ?? [])
      .map((c) => ({ collection: c.id, perm: m.accessAll ? Permission.Manage : (m.access[c.id] ?? null) }));
  }

  private add(n: Node) {
    if (this.nodes.has(n.id)) throw new Error(`duplicate node "${n.id}"`);
    if (n.id !== "root") {
      const was = this.bySlug.get(n.slug);
      if (was) throw new Error(`duplicate slug "${n.slug}": ${was} and ${n.id}`);
      this.bySlug.set(n.slug, n.id);
    }
    this.nodes.set(n.id, n);
  }

  /// A slug unique in the graph: the name's, with a number when taken.
  /// Slugs are only ever added, so every number below the one a base last
  /// stopped at is still taken: the count resumes there instead of walking
  /// again from 2 (a vault with a hundred "GitHub" items).
  /// A name's slug, worked out once while the graph is built: an item's
  /// name is slugged for its slug and again for its alias.
  private slugOf(name: string): string {
    const memo = this.slugMemo;
    if (!memo) return slugify(name);
    let s = memo.get(name);
    if (s === undefined) memo.set(name, (s = slugify(name)));
    return s;
  }
  private freeSlug(base: string): string {
    const b = this.slugOf(base) || "item";
    if (!this.bySlug.has(b)) return b;
    let i = this.slugNext.get(b) ?? 2;
    while (this.bySlug.has(`${b}-${i}`)) i++;
    this.slugNext.set(b, i);
    return `${b}-${i}`;
  }

  private build() {
    const { items, folders, orgs, collections, members } = this.catalog;
    const policies = this.catalog.policies ?? [];
    const contributions = this.contributions;
    const extra = new Map<string, ExtraSignal>();
    for (const c of contributions) for (const [id, s] of Object.entries(c.signals ?? {})) extra.set(id, s);
    // An item's state is read many times while the graph is built (each
    // list it stands in takes its level): it is worked out once.
    const states = new Map<Item, ReturnType<typeof itemState>>();
    const sigs = new Map<Item, Signal[]>();
    const sigsOf = (i: Item) => {
      let xs = sigs.get(i);
      if (!xs) sigs.set(i, (xs = settledSignals(i, this.catalog, this.now)));
      return xs;
    };
    const state = (i: Item) => {
      let st = states.get(i);
      if (!st) states.set(i, (st = itemStateOf(sigsOf(i)[0]!, i, this.catalog, extra.get(i.id))));
      return st;
    };
    const live = items.filter((i) => !i.deleted);
    // Who belongs where, in one pass each, in the catalogue's order.
    const liveOf = groupBy(live, (i) => i.orgId);
    const membersOf = groupBy(members, (m) => m.orgId);
    const policiesOf = groupBy(policies, (p) => p.orgId);
    const collectionsOf = groupBy(collections, (c) => c.orgId);
    const collOrg = new Map(collections.map((c) => [c.id, c.orgId]));
    const inCollection = new Map<string, Item[]>();
    for (const i of live) {
      if (!i.orgId) continue;
      for (const c of i.collectionIds) {
        if (collOrg.get(c) !== i.orgId) continue;
        const xs = inCollection.get(c);
        if (!xs) inCollection.set(c, [i]);
        else if (xs[xs.length - 1] !== i) xs.push(i);
      }
    }
    const lvl = (xs: Item[]) => worst(xs.map((i) => state(i).level));
    const key = (k: Key, args?: Record<string, string | number | Text>): Text => (args ? { key: k, args } : { key: k });
    const itemId = (i: Item) => `item:${i.id}`;

    const place = (i: Item): string[] => {
      if (i.deleted) return ["trash"];
      if (i.orgId) {
        const c = i.collectionIds[0];
        return c ? [`org:${i.orgId}`, `org:${i.orgId}/collections`, `collection:${c}`] : [`org:${i.orgId}`];
      }
      return i.folderId ? ["personal", `folder:${i.folderId}`] : ["personal"];
    };

    const sections = (orgId: string): string[] => [
      `org:${orgId}/collections`,
      ...(membersOf.has(orgId) ? [`org:${orgId}/members`, `org:${orgId}/access`] : []),
      `org:${orgId}/attention`,
      ...(policiesOf.has(orgId) ? [`org:${orgId}/policies`] : []),
    ];

    const dead = items.filter((i) => i.deleted);
    const root: Node = {
      id: "root",
      kind: NodeKind.Root,
      slug: "",
      name: key("root"),
      icon: "vault",
      level: lvl(live),
      home: [],
      kids: () => [
        { id: "all" },
        { gap: true },
        { id: "personal" },
        ...orgs.map((o) => ({ id: `org:${o.id}` })),
        ...(contributions.length ? [{ gap: true } as const, ...contributions.map((c) => ({ id: c.root.id }))] : []),
        ...(dead.length ? [{ id: "trash" }] : []),
        ...(this.settings.length ? [{ id: SETTINGS_ID }] : []),
        ...(this.places.length ? [{ heading: key("places") }, ...this.places.map((p) => ({ place: p.id }))] : []),
      ],
    };
    this.add(root);
    // The settings come before the vault's things: their words are fixed, an
    // item named "Settings" takes the next free slug, not theirs.
    if (this.settings.length) {
      const pages = this.settings;
      this.add({ id: SETTINGS_ID, kind: NodeKind.Settings, slug: SETTINGS_ID, name: key("set.title"), icon: "settings", level: Level.Unknown, home: [SETTINGS_ID], kids: () => pages.map((p) => ({ id: pageId(p), sub: key(pageSub(p)) })), doc: () => settingsDoc(pages) });
      for (const p of pages) this.add({ id: pageId(p), kind: NodeKind.SettingsPage, slug: `${SETTINGS_ID}-${p}`, name: key(PAGE_NAME[p]), icon: PAGE_ICON[p], level: Level.Unknown, home: [SETTINGS_ID, pageId(p)], doc: () => pageDoc(p) });
    }
    const personal = live.filter((i) => !i.orgId);
    const inFolder = groupBy(personal, (i) => i.folderId);
    this.add({
      id: "all",
      kind: NodeKind.All,
      slug: "all",
      name: key("all"),
      icon: "vault",
      sub: key("count.items", { n: live.length }),
      level: lvl(live),
      home: ["all"],
      wide: true,
      kids: () => {
        const groups: [Text, Item[]][] = [[key("personal"), personal], ...orgs.map((o): [Text, Item[]] => [{ raw: o.name }, liveOf.get(o.id) ?? []])];
        const shown = groups.filter(([, xs]) => xs.length);
        return shown.flatMap(([h, xs]) => [...(shown.length > 1 ? [{ heading: h }] : []), ...xs.map((i) => ({ id: itemId(i) }))]);
      },
    });
    this.add({
      id: "personal",
      kind: NodeKind.Personal,
      slug: "personal",
      name: key("personal"),
      icon: "person",
      sub: key("personal.sub", { n: personal.length }),
      level: lvl(personal),
      home: ["personal"],
      kids: () => [...folders.map((f) => ({ id: `folder:${f.id}` })), ...personal.filter((i) => !i.folderId).map((i) => ({ id: itemId(i) }))],
    });
    for (const f of folders) {
      const xs = inFolder.get(f.id) ?? [];
      this.add({
        id: `folder:${f.id}`,
        kind: NodeKind.Folder,
        slug: this.freeSlug(f.name),
        name: { raw: f.name },
        icon: "folder",
        count: xs.length,
        level: lvl(xs),
        home: ["personal", `folder:${f.id}`],
        wide: true,
        kids: () => xs.map((i) => ({ id: itemId(i) })),
      });
    }
    orgs.forEach((o, oi) => {
      const oid = `org:${o.id}`;
      const xs = liveOf.get(o.id) ?? [];
      const ms = membersOf.get(o.id) ?? [];
      const cs = collectionsOf.get(o.id) ?? [];
      const ps = policiesOf.get(o.id) ?? [];
      const role = key(`role.${o.role}` as Key);
      this.add({
        id: oid,
        kind: NodeKind.Org,
        slug: this.freeSlug(o.name),
        name: { raw: o.name },
        icon: "org",
        hue: ORG_HUES[oi % ORG_HUES.length]!,
        sub: ms.length ? key("org.sub", { role, n: ms.length }) : role,
        level: worst([lvl(xs), ...ms.map(memberLevel), ...ps.map(policyLevel)]),
        home: [oid],
        kids: () => sections(o.id).map((id) => ({ id })),
      });
      this.add({
        id: `${oid}/collections`,
        kind: NodeKind.Section,
        slug: this.freeSlug(`${o.name}-collections`),
        name: key("section.collections"),
        icon: "stack",
        count: cs.length,
        level: lvl(xs),
        home: [oid, `${oid}/collections`],
        kids: () => cs.map((c) => ({ id: `collection:${c.id}` })),
      });
      for (const c of cs) {
        const cx = inCollection.get(c.id) ?? [];
        this.add({
          id: `collection:${c.id}`,
          kind: NodeKind.Collection,
          slug: this.freeSlug(c.name),
          name: { raw: c.name },
          icon: "stack",
          count: cx.length,
          level: lvl(cx),
          home: [oid, `${oid}/collections`, `collection:${c.id}`],
          wide: true,
          kids: () => cx.map((i) => ({ id: itemId(i) })),
        });
      }
      if (ms.length) {
        const confirmed = ms.filter((m) => m.status === MemberStatus.Confirmed);
        const pending = ms.filter((m) => m.status !== MemberStatus.Confirmed);
        this.add({
          id: `${oid}/members`,
          kind: NodeKind.Section,
          slug: this.freeSlug(`${o.name}-members`),
          name: key("section.members"),
          icon: "people",
          count: ms.length,
          level: worst(ms.map(memberLevel)),
          home: [oid, `${oid}/members`],
          wide: true,
          kids: () => [
            ...(confirmed.length ? [{ heading: key("members.confirmed") }, ...confirmed.map((m) => ({ id: `member:${m.id}` }))] : []),
            ...(pending.length ? [{ heading: key("members.pending") }, ...pending.map((m) => ({ id: `member:${m.id}` }))] : []),
          ],
        });
        this.add({
          id: `${oid}/access`,
          kind: NodeKind.Section,
          slug: this.freeSlug(`${o.name}-access`),
          name: key("section.access"),
          icon: "map",
          sub: key("access.sub"),
          level: worst([lvl(xs), ...ms.map(memberLevel)]),
          home: [oid, `${oid}/access`],
          map: { kind: MapKind.Access, anchor: oid },
        });
        for (const m of ms) {
          const st = memberState(m);
          const reach = this.reach(m);
          this.add({
            id: `member:${m.id}`,
            kind: NodeKind.Member,
            slug: this.freeSlug(m.name ?? m.email.split("@")[0]!),
            name: { raw: m.name ?? m.email },
            icon: "person",
            sub: m.isYou ? key("member.subYou", { role: key(`role.${m.role}` as Key) }) : key(`role.${m.role}` as Key),
            level: st.level,
            why: st.why,
            member: m,
            home: [oid, `${oid}/members`, `member:${m.id}`],
            wide: true,
            result: { group: ResultGroup.Members, kind: ResultKind.Member, orgId: o.id, place: [oid], haystack: `${m.name ?? ""} ${m.email} ${m.role}`.toLowerCase() },
            kids: () => {
              const can = reach.filter((r) => r.perm);
              const none = reach.filter((r) => !r.perm);
              return [
                ...(can.length ? [{ heading: key("reach.can") }, ...can.map((r) => ({ id: `collection:${r.collection}`, sub: key(`perm.${r.perm!}` as Key) }))] : []),
                ...(none.length ? [{ heading: key("reach.none") }, ...none.map((r) => ({ id: `collection:${r.collection}`, sub: key("perm.closed"), off: true }))] : []),
              ];
            },
          });
        }
      }
      const loud = xs.filter((i) => isLoud(state(i).level)).sort((a, b) => rankOf(state(a).level) - rankOf(state(b).level));
      this.add({
        id: `${oid}/attention`,
        kind: NodeKind.Section,
        slug: this.freeSlug(`${o.name}-attention`),
        name: key("section.attention"),
        icon: "pulse",
        count: loud.length,
        level: lvl(loud),
        home: [oid, `${oid}/attention`],
        wide: true,
        kids: () => loud.map((i) => ({ id: itemId(i) })),
      });
      if (ps.length)
        this.add({
          id: `${oid}/policies`,
          kind: NodeKind.Section,
          slug: this.freeSlug(`${o.name}-policies`),
          name: key("section.policies"),
          icon: "policy",
          count: ps.length,
          level: worst(ps.map(policyLevel)),
          home: [oid, `${oid}/policies`],
        });
    });
    for (const c of contributions) {
      // A plugin's word may already be a folder's or an organisation's
      // ("Kubernetes"): the plugin's step takes the next free one.
      this.add({ ...c.root, slug: this.freeSlug(c.root.slug), home: [c.root.id] });
      for (const n of c.nodes) {
        const home = c.homes[n.id];
        if (!home) throw new Error(`plugin node "${n.id}" has no home`);
        if (home[0] !== c.root.id || home[home.length - 1] !== n.id) throw new Error(`plugin node "${n.id}" has a home outside its plugin`);
        this.add({ ...n, slug: this.freeSlug(n.slug), home });
      }
    }
    if (dead.length)
      this.add({
        id: "trash",
        kind: NodeKind.Trash,
        slug: "trash",
        name: key("section.trash"),
        icon: "trash",
        count: dead.length,
        level: Level.Unknown,
        home: ["trash"],
        wide: true,
        kids: () => dead.map((i) => ({ id: itemId(i) })),
      });
    const copies = (i: Item) => duplicatesOf(i, this.catalog).length;
    for (const i of items) {
      const home = [...place(i), itemId(i)];
      const st = state(i);
      this.add({
        id: itemId(i),
        kind: NodeKind.Item,
        slug: this.freeSlug(i.name),
        name: { raw: i.name },
        icon: ITEM_ICON[i.kind],
        sub: i.subtitle ? { raw: i.subtitle } : key(`kind.${i.kind}` as Key),
        subMono: i.kind === ItemKind.SshKey,
        level: st.level,
        why: st.why,
        short: st.short,
        item: i,
        ...(copies(i) > 0 ? { copies: copies(i) } : {}),
        home,
        // A deleted item is found in the trash, not by a search of the vault.
        ...(i.deleted
          ? {}
          : {
              result: {
                group: ResultGroup.Items as const,
                kind: i.kind,
                orgId: i.orgId,
                place: home.slice(0, -1),
                haystack: [i.name, i.subtitle, ...i.uris, ...Object.values(i.tags), ...sigsOf(i).map((s) => s.key)].filter(Boolean).join(" ").toLowerCase(),
              },
            }),
      });
    }
    const orgByNode = new Map<string, Org>();
    for (const x of this.catalog.orgs) if (!orgByNode.has(`org:${x.id}`)) orgByNode.set(`org:${x.id}`, x);
    for (const n of this.nodes.values()) {
      const o = n.home[0]?.startsWith("org:") ? orgByNode.get(n.home[0]) : undefined;
      if (o) n.org = o;
    }
    // Words in every language reach a step: a section's name read in each
    // dictionary is an alias, so "участники" and "members" both step there.
    for (const n of this.nodes.values()) {
      if (n.id === "root") continue;
      // A name from the data is one word in every language (`textsOf` reads
      // it lowercased, which slugging does anyway).
      for (const w of "raw" in n.name ? [this.slugOf(n.name.raw)] : textsOf(n.name).map(slugify)) if (w && !this.bySlug.has(w) && !this.aliases.has(w)) this.aliases.set(w, n.id);
    }
  }
}

/// A list split by a key, each part in the list's order.
function groupBy<T, K>(xs: readonly T[], key: (x: T) => K): Map<K, T[]> {
  const out = new Map<K, T[]>();
  for (const x of xs) {
    const k = key(x);
    const g = out.get(k);
    if (g) g.push(x);
    else out.set(k, [x]);
  }
  return out;
}

const RANKS: Record<Level, number> = { [Level.Critical]: 0, [Level.Action]: 1, [Level.Warning]: 2, [Level.Healthy]: 3, [Level.Unknown]: 4 };
const rankOf = (l: Level) => RANKS[l];

/// A node's name in the language of the moment.
export const nameOf = (n: Node): string => text(n.name);
