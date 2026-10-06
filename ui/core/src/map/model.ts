// The maps' models, built from the graph: an item's relations, an
// organisation's access, a plugin's topology. Every point is a node of the
// graph (or a plain picture with `nav: null`), so a point under the pointer
// lights its row and a click steps the columns there. Pure; a model is built
// once per graph and map.
import type { Key, Text } from "../i18n";
import { isLoud, type Directory, type Node, NodeKind, ResultGroup, MapKind } from "../path/directory";
import { orgFindings } from "../model/findings";
import { reusePartners, serviceGroups } from "../model/reasons";
import type { MarkSpec } from "../doc/spec";
import { ItemKind, Level, type Member, Permission, MemberStatus } from "../model/types";
import type { MapRef } from "../path/query";
import { EdgeKind, type Finding, type MapEdge, type MapModel, type MapNode, Shape } from "./types";

const SHAPE: Record<ItemKind, Shape> = { [ItemKind.Login]: Shape.Login, [ItemKind.Card]: Shape.Card, [ItemKind.Identity]: Shape.Identity, [ItemKind.SecureNote]: Shape.Note, [ItemKind.SshKey]: Shape.Ssh };
const KIND_KEY: Record<ItemKind, Key> = { [ItemKind.Login]: "kind.login", [ItemKind.Card]: "kind.card", [ItemKind.Identity]: "kind.identity", [ItemKind.SecureNote]: "kind.secure_note", [ItemKind.SshKey]: "kind.ssh_key" };

export const initials = (s: string) =>
  s
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w[0]!)
    .join("")
    .slice(0, 2)
    .toUpperCase();

/// An item as a point: its type's shape, the state's mark inside, and the
/// reason in a word on its second line.
export function itemPoint(dir: Directory, id: string, lane: number): MapNode {
  const n = dir.node(id);
  const it = n.item!;
  const marks: MarkSpec[] = isLoud(n.level) ? [{ level: n.level, text: n.short! }] : [];
  return { id, lane, nav: id, shape: SHAPE[it.kind], level: n.level, label: n.name, sub: { key: KIND_KEY[it.kind] }, marks };
}

/// A folder or a collection as a point.
function containerPoint(dir: Directory, id: string, lane: number): MapNode {
  const n = dir.node(id);
  const coll = n.kind === NodeKind.Collection;
  const org = dir.orgOf(id);
  return {
    id,
    lane,
    nav: id,
    shape: coll ? Shape.Coll : Shape.Folder,
    level: isLoud(n.level) ? n.level : Level.Healthy,
    label: n.name,
    sub: coll ? { key: "map.collectionOf", args: { org: org ? dir.node(org).name : { key: "personal" } } } : { key: "map.folderOf", args: { owner: { key: "personal" } } },
    marks: [],
  };
}

function memberPoint(dir: Directory, m: Member, lane: number): MapNode {
  const id = `member:${m.id}`;
  const n = dir.node(id);
  const marks: MarkSpec[] = [];
  if (m.twoFactor === false) marks.push({ level: Level.Warning, text: { key: "map.noTwoFactor" } });
  if (m.status === MemberStatus.Accepted) marks.push({ level: Level.Action, text: { key: "map.pending" } });
  if (m.status === MemberStatus.Invited) marks.push({ level: Level.Unknown, text: { key: "status.invited" } });
  return {
    id,
    lane,
    nav: id,
    avatar: initials(m.name ?? m.email),
    invited: m.status === MemberStatus.Invited,
    level: n.level,
    label: m.isYou ? { key: "map.you", args: { name: m.name ?? m.email } } : n.name,
    sub: { key: `role.${m.role}` as Key },
    marks,
  };
}

/// A plugin's node as a point: its shape from its kind of result.
export function pluginPoint(dir: Directory, id: string, lane: number): MapNode {
  const n = dir.node(id);
  const shape: Shape = n.result?.group === ResultGroup.Clusters ? Shape.Cluster : Shape.Host;
  const marks: MarkSpec[] = isLoud(n.level) || n.level === Level.Unknown ? [{ level: n.level, text: n.short ?? n.why ?? { key: `level.${n.level}` as Key } }] : [];
  // The short name: the lane's caption already says what it is.
  return { id, lane, nav: id, shape, level: n.level, label: n.rowName ?? n.name, mono: n.mono ?? false, sub: n.sub ?? { raw: "" }, marks };
}

export function pointOf(dir: Directory, id: string, lane: number): MapNode {
  const n = dir.node(id);
  if (n.kind === NodeKind.Item) return itemPoint(dir, id, lane);
  if (n.kind === NodeKind.Folder || n.kind === NodeKind.Collection) return containerPoint(dir, id, lane);
  if (n.kind === NodeKind.Member) return memberPoint(dir, n.member!, lane);
  return pluginPoint(dir, id, lane);
}

const PERM_EDGE: Record<Permission, EdgeKind> = { [Permission.Manage]: EdgeKind.Manage, [Permission.Edit]: EdgeKind.Edit, [Permission.EditHidden]: EdgeKind.Edit, [Permission.Read]: EdgeKind.Read, [Permission.ReadHidden]: EdgeKind.Hidden };

/// Who sees a collection, in words: the access map's business, a line here.
function seenBy(dir: Directory, p: MapNode) {
  const cid = p.id.slice("collection:".length);
  const ms = dir.catalog.members.filter((m) => m.status !== MemberStatus.Invited && (m.accessAll || m.access[cid]) && dir.has(`member:${m.id}`));
  const bad = ms.filter((m) => m.twoFactor === false).length;
  const org = dir.orgOf(p.id);
  p.sub = { key: "map.seenBy", args: { org: org ? dir.node(org).name : { raw: "" }, n: ms.length } };
  if (bad) {
    p.marks = [{ level: Level.Warning, text: { key: "map.withoutTwoFactor", args: { n: bad } } }];
    p.level = Level.Warning;
  }
  return { n: ms.length, bad };
}

export function relationsModel(dir: Directory, itemId: string): MapModel {
  const anchor = dir.node(itemId);
  const it = anchor.item;
  if (!it) throw new Error(`relations of "${itemId}", which is not an item`);
  const nodes: MapNode[] = [];
  const edges: MapEdge[] = [];
  const add = (p: MapNode) => {
    if (!nodes.some((x) => x.id === p.id)) nodes.push(p);
  };
  const home = anchor.home[anchor.home.length - 2]!;
  add(containerPoint(dir, home, 0));
  add({ ...itemPoint(dir, itemId, 1), anchor: true });
  edges.push({ a: home, b: itemId, kind: EdgeKind.In, words: { key: it.orgId ? "map.inCollection" : "map.inFolder" } });
  const partners = reusePartners(it, dir.catalog);
  for (const p of partners) {
    add(itemPoint(dir, `item:${p.id}`, 2));
    edges.push({ a: itemId, b: `item:${p.id}`, kind: EdgeKind.Svc, level: Level.Critical, words: { key: "map.samePassword" }, chip: true });
  }
  const service = serviceWord(it.name);
  if (service)
    for (const s of (serviceGroups(dir.catalog.items).get(service) ?? []).filter((i) => i.id !== it.id && !partners.includes(i))) {
      add(itemPoint(dir, `item:${s.id}`, 2));
      edges.push({ a: itemId, b: `item:${s.id}`, kind: EdgeKind.Svc, words: { key: "map.sameService" } });
    }
  const links = dir.links();
  for (const l of links.filter((x) => x.to === itemId && dir.has(x.from))) {
    add(pointOf(dir, l.from, 2));
    edges.push({ a: itemId, b: l.from, kind: l.kind, ...(l.level ? { level: l.level } : {}), words: l.words, ...(l.level === Level.Critical ? { chip: true } : {}) });
  }
  // Where the ones it is tied to live, when that is somewhere else.
  for (const p of nodes.filter((x) => x.lane === 2)) {
    const n = dir.node(p.id);
    if (n.kind === NodeKind.Item) {
      const c = n.home[n.home.length - 2]!;
      if (c !== home && dir.has(c) && [NodeKind.Folder, NodeKind.Collection].includes(dir.node(c).kind)) {
        add(containerPoint(dir, c, 3));
        edges.push({ a: p.id, b: c, kind: EdgeKind.In, words: { key: n.item!.orgId ? "map.inCollection" : "map.inFolder" } });
      }
    } else
      for (const l of links.filter((x) => x.from === p.id && dir.has(x.to) && dir.node(x.to).kind !== NodeKind.Item)) {
        add(pointOf(dir, l.to, 3));
        edges.push({ a: p.id, b: l.to, kind: l.kind, words: l.words });
      }
  }
  const findings: Finding[] = [];
  for (const p of partners) findings.push({ level: Level.Critical, text: { key: "map.findSamePassword", args: { name: p.name } }, focus: `item:${p.id}` });
  for (const l of links.filter((x) => x.to === itemId && dir.has(x.from) && x.finding)) findings.push({ level: dir.node(l.from).level, text: l.finding!, focus: l.from });
  for (const p of nodes.filter((x) => x.shape === Shape.Coll)) {
    const { n, bad } = seenBy(dir, p);
    if (bad && p.lane > 1) findings.push({ level: Level.Warning, text: { key: "map.findSeenWithout", args: { coll: p.label, n, k: bad } }, focus: p.id });
  }
  if (!it.orgId) findings.push({ level: Level.Healthy, text: { key: "map.findOnlyYou" }, focus: home });
  const used = [...new Set(nodes.map((n) => n.lane))].sort((a, b) => a - b);
  for (const n of nodes) n.lane = used.indexOf(n.lane);
  const LANES: Key[] = ["map.laneWhere", "map.laneItem", "map.laneTied", "map.laneTheirs"];
  return {
    nodes,
    edges,
    lanes: used.map((l) => ({ key: LANES[l]! })),
    pivot: used.indexOf(2) >= 0 ? used.indexOf(2) : 1,
    title: { key: "map.relationsOf", args: { name: anchor.name } },
    place: { key: "map.relationsPlace", args: { place: placeText(dir, anchor), kind: { key: KIND_KEY[it.kind] }, n: nodes.length - 1 } },
    findings,
    legend: [
      { kind: EdgeKind.Svc, level: Level.Critical, text: { key: "map.samePassword" } },
      { kind: EdgeKind.Svc, text: { key: "map.sameService" } },
      { kind: EdgeKind.In, text: { key: "map.livesIn" } },
      { kind: EdgeKind.Token, text: { key: "map.token" } },
      { kind: EdgeKind.Route, text: { key: "map.keyAccepted" } },
      { kind: EdgeKind.Refused, level: Level.Critical, text: { key: "map.refused" } },
    ],
  };
}

const serviceWord = (name: string) => {
  const m = /^(.+?)\s+[—–-]\s+/.exec(name);
  return m ? m[1]!.trim().toLowerCase() : null;
};

/// The path a node lives under, as one text: "Personal › Work".
export function placeText(dir: Directory, n: Node): Text {
  const ids = n.home.slice(0, -1);
  if (!ids.length) return { key: "root" };
  return ids.slice(1).reduce<Text>((acc, id) => ({ key: "map.placeJoin", args: { a: acc, b: dir.node(id).name } }), dir.node(ids[0]!).name);
}

export function accessModel(dir: Directory, orgNode: string): MapModel {
  const oid = orgNode.slice("org:".length);
  const ms = dir.catalog.members.filter((m) => m.orgId === oid);
  const cs = dir.catalog.collections.filter((c) => c.orgId === oid);
  const nodes: MapNode[] = [];
  const edges: MapEdge[] = [];
  for (const m of ms) nodes.push(memberPoint(dir, m, 0));
  let itemCount = 0;
  for (const c of cs) {
    const p = containerPoint(dir, `collection:${c.id}`, 1);
    const seers = ms.filter((m) => m.accessAll || m.access[c.id]).length;
    p.sub = { key: "map.collectionSub", args: { items: { key: "count.items", args: { n: dir.node(p.id).count ?? 0 } }, n: seers } };
    nodes.push(p);
  }
  const placed = new Set(nodes.map((x) => x.id));
  for (const c of cs)
    for (const id of dir.kidIds(`collection:${c.id}`)) {
      if (placed.has(id)) continue;
      placed.add(id);
      nodes.push(itemPoint(dir, id, 2));
      itemCount++;
      edges.push({ a: `collection:${c.id}`, b: id, kind: EdgeKind.In, words: { key: "map.inCollection" } });
    }
  const crits = new Map<string, boolean>();
  const critColl = (cid: string) => {
    let c = crits.get(cid);
    if (c === undefined) crits.set(cid, (c = dir.kidIds(`collection:${cid}`).some((id) => dir.node(id).level === Level.Critical)));
    return c;
  };
  for (const m of ms)
    for (const r of dir.reach(m)) {
      if (!r.perm) continue;
      const perm: Text = m.accessAll ? { key: "map.permAll", args: { perm: { key: `perm.${r.perm}` as Key } } } : { key: `perm.${r.perm}` as Key };
      const a = `member:${m.id}`;
      const b = `collection:${r.collection}`;
      if (m.status === MemberStatus.Invited) {
        edges.push({ a, b, kind: EdgeKind.Invite, words: { key: "map.invitedPerm", args: { perm } } });
        continue;
      }
      const crit = m.twoFactor === false && critColl(r.collection);
      const coll = dir.node(b).name;
      edges.push({
        a,
        b,
        kind: PERM_EDGE[r.perm],
        words: crit ? { key: "map.readsWithout", args: { coll } } : m.twoFactor === false ? { key: "map.noTwoFactorPerm", args: { perm } } : perm,
        ...(crit ? { level: Level.Critical as const, chip: true } : m.twoFactor === false ? { level: Level.Warning as const } : {}),
      });
    }
  const findings: Finding[] = orgFindings(dir, orgNode)
    .filter((f) => f.map)
    .map((f) => ({ level: f.level, text: f.title, focus: f.focus }));
  return {
    nodes,
    edges,
    lanes: [{ key: "map.laneMembers" }, { key: "map.laneCollections" }, { key: "map.laneItems" }],
    pivot: 0,
    title: { key: "map.accessOf", args: { name: dir.node(orgNode).name } },
    place: { key: "map.accessPlace", args: { members: { key: "count.members", args: { n: ms.length } }, colls: { key: "count.collections", args: { n: cs.length } }, items: { key: "count.items", args: { n: itemCount } } } },
    findings,
    legend: [
      { kind: EdgeKind.Manage, text: { key: "perm.manage" } },
      { kind: EdgeKind.Edit, text: { key: "perm.edit" } },
      { kind: EdgeKind.Read, text: { key: "perm.read" } },
      { kind: EdgeKind.Hidden, text: { key: "perm.readHidden" } },
      { kind: EdgeKind.Invite, text: { key: "map.invite" } },
    ],
  };
}

const CACHE = new WeakMap<Directory, Map<string, MapModel>>();

/// The model of a map, built once per graph.
export function mapModel(dir: Directory, m: MapRef): MapModel {
  let per = CACHE.get(dir);
  if (!per) CACHE.set(dir, (per = new Map()));
  const k = `${m.kind}:${m.anchor}`;
  let md = per.get(k);
  if (!md) {
    md = m.kind === MapKind.Relations ? relationsModel(dir, m.anchor) : m.kind === MapKind.Access ? accessModel(dir, m.anchor) : dir.topology(m.anchor);
    per.set(k, md);
  }
  return md;
}

/// Is a node a point of a map: what decides whether a step keeps the map open.
const POINTS = new WeakMap<MapModel, Set<string>>();
export function onMap(dir: Directory, m: MapRef | null, id: string | null): boolean {
  if (!m || !id) return false;
  const md = mapModel(dir, m);
  let ids = POINTS.get(md);
  if (!ids) POINTS.set(md, (ids = new Set(md.nodes.map((n) => n.id))));
  return ids.has(id);
}

/// The marks of a level, as a legend reads them.
export const levelText = (l: Level): Text => ({ key: `level.${l}` as Key });
