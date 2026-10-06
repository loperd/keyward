// What the line offers while a person types: the next steps, saved places,
// the keys a filter can use and their values, steps elsewhere in the graph,
// and the verbs that apply. Syntax shows only here and in the input; once
// taken, a piece is read back as a crumb. Pure.
import { text, textsOf, type Key, type Text } from "../i18n";
import { Level } from "../model/types";
import { isLoud, type Node, NodeKind, ResultGroup, MapKind } from "./directory";
import { isFilter, objectOf, STATES, TOKEN_KEYS, type PathState, type Query, TokenKey } from "./query";
import type { Place } from "./places";
import { isEnumValue } from "../model/enum";

/// What taking an option does: run a verb, write a token, take a step, run
/// a saved line, or start a filter key.
export enum OptionType {
  Verb = "verb",
  Token = "token",
  Step = "step",
  Run = "run",
  Key = "key",
}
export type Option = {
  group: Text;
  type: OptionType;
  /// What taking it writes: a slug, a token, a line, a verb's id.
  value: string;
  label: Text;
  /// The syntax it stands for, shown quietly on the right.
  syn: string;
  icon?: string;
  level?: Level;
  /// Not applicable here: shown, not chosen.
  na?: boolean;
};

const KEY_WORDS: Record<TokenKey, Key> = {
  [TokenKey.Org]: "key.org",
  [TokenKey.Member]: "key.member",
  [TokenKey.State]: "key.state",
  [TokenKey.Kind]: "key.kind",
  [TokenKey.Host]: "key.host",
  [TokenKey.In]: "key.in",
  [TokenKey.Item]: "key.item",
  [TokenKey.Map]: "key.map",
};
const KEY_ICON: Record<TokenKey, string | undefined> = { [TokenKey.Org]: "org", [TokenKey.Member]: "person", [TokenKey.State]: undefined, [TokenKey.Kind]: "filter", [TokenKey.Host]: "server", [TokenKey.In]: "filter", [TokenKey.Item]: "login", [TokenKey.Map]: "map" };
const KINDS: [string, Key][] = [
  ["login", "kind.login"],
  ["card", "kind.card"],
  ["note", "kind.secure_note"],
  ["identity", "kind.identity"],
  ["ssh", "kind.ssh_key"],
  ["host", "kind.host"],
  ["member", "kind.member"],
  ["cluster", "kind.cluster"],
];
const STATE_LEVEL: Record<string, Level> = { critical: Level.Critical, action: Level.Action, warning: Level.Warning, healthy: Level.Healthy, unknown: Level.Unknown, attention: Level.Action };

/// The values a key offers: a slug or a pattern, and its human name.
function values(q: Query, k: TokenKey): [string, Text][] {
  const nodes = q.dir.list();
  switch (k) {
    case TokenKey.Org:
      return q.dir.ofKind(NodeKind.Org).map((n) => [n.slug, n.name]);
    case TokenKey.Member:
      return q.dir.ofKind(NodeKind.Member).map((n) => [n.slug, n.name]);
    case TokenKey.State:
      return Object.keys(STATES).map((s) => [s, { key: (s === "attention" ? "level.attention" : `level.${s}`) as Key }]);
    case TokenKey.Kind:
      return KINDS.map(([v, key]) => [v, { key }]);
    case TokenKey.Host: {
      const hosts = nodes.filter((n) => n.result?.group === ResultGroup.Hosts);
      const zones = [...new Set(hosts.map((h) => text(h.name).split(".")[1]).filter((z): z is string => !!z))];
      return [...zones.map((z): [string, Text] => [`*.${z}.*`, { key: "suggest.allOf", args: { zone: z } }]), ...hosts.map((h): [string, Text] => [h.slug, h.name])];
    }
    case TokenKey.In:
      return nodes.filter((n) => n.kind === NodeKind.Folder || n.kind === NodeKind.Collection).map((n) => [n.slug, n.name]);
    case TokenKey.Item:
      return q.dir.ofKind(NodeKind.Item).filter((n) => n.result).map((n) => [n.slug, n.name]);
    case TokenKey.Map:
      return [
        ...nodes.filter((n) => n.map).map((n): [string, Text] => [n.slug, n.map!.kind === MapKind.Access ? { key: "map.accessOf", args: { name: q.dir.node(n.map!.anchor).name } } : n.name]),
        ...q.dir.ofKind(NodeKind.Item).filter((n) => n.result).map((n): [string, Text] => [n.slug, { key: "map.relationsOf", args: { name: n.name } }]),
      ];
  }
}

/// The same for a node of the graph, its words read once per graph.
const nodeMatches = (q: Query, n: Node, frag: string) => !frag || n.slug.includes(frag) || q.dir.searchTexts(n.id).some((x) => x.includes(frag));

export function suggest(q: Query, st: PathState, input: string, places: Place[]): Option[] {
  const frag = (input.split(/\s+/).pop() ?? "").toLowerCase();
  const obj = objectOf(st.segs);
  const objName = obj ? q.dir.node(obj).name : null;
  const out: Option[] = [];
  const acts: Text = objName ? { key: "suggest.actsOn", args: { name: objName } } : { key: "suggest.acts" };
  if (input.includes(">")) {
    const v = input.slice(input.indexOf(">") + 1).trim().toLowerCase();
    const on = obj ? q.dir.node(obj) : null;
    q.verbs
      .filter((x) => x.id.startsWith(v) || textsOf(x.name).some((w) => w.includes(v)))
      .map((x) => ({ x, ok: x.applies(on) }))
      .sort((a, b) => Number(b.ok) - Number(a.ok))
      .forEach(({ x, ok }) => out.push({ group: acts, type: OptionType.Verb, value: x.id, label: x.name, syn: `> ${x.id}`, icon: x.icon ?? "verb", ...(ok ? {} : { na: true }) }));
    return out.slice(0, 14);
  }
  const colon = frag.indexOf(":");
  if (colon >= 0) {
    // boundary: the key typed before the colon, a filter key or nothing to offer.
    const k = frag.slice(0, colon);
    const pv = frag.slice(colon + 1);
    if (!isEnumValue(TokenKey, k)) return [];
    for (const [v, label] of firstOf(values(q, k), 12, ([v, l]) => v.startsWith(pv) || textsOf(l).some((x) => x.includes(pv)))) {
      const icon = KEY_ICON[k];
      out.push({ group: { key: KEY_WORDS[k] }, type: OptionType.Token, value: `${k}:${v}`, label, syn: `${k}:${v}`, ...(icon ? { icon } : {}), ...(k === TokenKey.State ? { level: STATE_LEVEL[v]! } : {}) });
    }
    return out;
  }
  const next = q.listAfter(st.segs).filter((id) => nodeMatches(q, q.dir.node(id), frag));
  const last = st.segs[st.segs.length - 1];
  const here: Text = !last ? { key: "root" } : isFilter(last) ? { raw: q.filterName(last.filter) } : q.dir.node(last.id).name;
  for (const id of next.slice(0, 6)) {
    const n = q.dir.node(id);
    out.push({ group: { key: "suggest.next", args: { here } }, type: OptionType.Step, value: n.slug, label: n.name, syn: n.slug, icon: n.icon, ...(isLoud(n.level) ? { level: n.level } : {}) });
  }
  if (!frag) for (const p of places) out.push({ group: { key: "places" }, type: OptionType.Run, value: p.line, label: p.name, syn: p.line, ...(p.level ? { level: p.level } : { icon: p.icon! }) });
  if (!frag && !st.segs.length) {
    for (const n of q.dir.list().filter((x) => x.map)) out.push({ group: { key: "suggest.maps" }, type: OptionType.Run, value: `map:${n.slug}`, label: n.map!.kind === MapKind.Access ? { key: "map.accessOf", args: { name: q.dir.node(n.map!.anchor).name } } : n.name, syn: `map:${n.slug}`, icon: "map" });
    const first = q.dir.list().find((x) => x.kind === NodeKind.Item && x.result && x.level === Level.Critical);
    if (first) out.push({ group: { key: "suggest.maps" }, type: OptionType.Run, value: `map:${first.slug}`, label: { key: "map.relationsOf", args: { name: first.name } }, syn: `map:${first.slug}`, icon: "map" });
  }
  for (const k of TOKEN_KEYS.filter((x) => !frag || x.startsWith(frag)).slice(0, frag ? 3 : 4))
    out.push({ group: { key: "suggest.refine" }, type: OptionType.Key, value: `${k}:`, label: { key: KEY_WORDS[k] }, syn: `${k}:`, icon: "filter" });
  if (frag) {
    const near = new Set(next);
    for (const n of firstOf(q.dir.list(), 4, (x) => x.id !== "root" && !near.has(x.id) && nodeMatches(q, x, frag)))
      out.push({
        group: { key: "suggest.elsewhere" },
        type: OptionType.Run,
        value: q.serialize({ segs: n.home.map((x) => ({ id: x })), map: null, verb: null, arg: "" }),
        label: n.name,
        syn: n.home.map((x) => q.dir.node(x).slug).join(" › "),
        icon: n.icon,
        ...(isLoud(n.level) ? { level: n.level } : {}),
      });
  }
  if (!frag && obj) {
    const on = q.dir.node(obj);
    for (const v of q.verbs.filter((x) => x.applies(on) && x.id !== "lock").slice(0, 4)) out.push({ group: acts, type: OptionType.Verb, value: v.id, label: v.name, syn: `> ${v.id}`, icon: v.icon ?? "verb" });
  }
  return out.slice(0, 14);
}

/// The first `max` of a list that pass, in its order: `filter().slice()`
/// without walking the rest.
function firstOf<T>(xs: readonly T[], max: number, ok: (x: T) => boolean): T[] {
  const out: T[] = [];
  for (const x of xs) {
    if (out.length >= max) break;
    if (ok(x)) out.push(x);
  }
  return out;
}

/// The path as it stands, without its verb: what typed words are added to.
export const pathLine = (q: Query, st: PathState) => q.serialize({ segs: st.segs, map: st.map, verb: null, arg: "" });
/// The path with typed words after it.
export const lineWith = (q: Query, st: PathState, typed: string) => [pathLine(q, st), typed.trim()].filter(Boolean).join(" ");

/// What taking an option does: a line to commit (and whether the
/// suggestions open again on it), or new words for the input.
export type Taken = { line: string; reopen: boolean } | { input: string };
export function take(q: Query, st: PathState, input: string, o: Option): Taken {
  const words = input.split(/\s+/);
  words.pop();
  const rest = words.join(" ").replace(/>.*$/, "").trim();
  const base = lineWith(q, st, rest);
  switch (o.type) {
    case OptionType.Run:
      return { line: o.value, reopen: false };
    case OptionType.Key:
      return { input: (rest ? rest + " " : "") + o.value };
    case OptionType.Token:
    case OptionType.Step:
      // A choice is made: the list goes away. Typing (or ↓) opens it again
      // for the next step.
      return { line: `${base} ${o.value}`.trim(), reopen: false };
    case OptionType.Verb:
      return { line: `${base} > ${o.value}`.trim(), reopen: false };
  }
}

/// The first option that can be chosen.
export const firstChoice = (opts: Option[]) => Math.max(0, opts.findIndex((o) => !o.na));
