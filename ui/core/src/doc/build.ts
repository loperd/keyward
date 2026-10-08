// The core's documents: one per kind of node, written in the document
// vocabulary (`spec.ts`). What a page says is decided here, from the graph and
// the opened item; the inspector only draws it. Pure.
import { customValue, isCustomKind, siteHost } from "../model/fields";
import type { Args, Key, Text } from "../i18n";
import { duplicatesOf, partnerName, placeOf as itemPlace, reusedWith, sameService, expiryText } from "../model/reasons";
import { orgFindings } from "../model/findings";
import { ago } from "../model/time";
import { isLoud, policyLevel, type Directory, type Node, NodeKind, MapKind } from "../path/directory";
import { type Field, type ItemDetail, Level, type Member, type Policy, ItemKind, MemberStatus, PolicyType, Permission, SecretField } from "../model/types";
import { type Action, type Block, type DocSpec, type Lead, type MarkSpec, type Section, LeadTile, Hue, SkeletonKind } from "./spec";
import type { Place } from "../path/places";
import { collectionActions, invite, memberActions, newCollection, verbOn } from "./org-actions";

export type DocContext = { dir: Directory; detail: ItemDetail | null; server: string; places: Place[] };

const k = (key: Key, args?: Args): Text => (args ? { key, args } : { key });
const mark = (level: Level, text: Text): MarkSpec => ({ level, text });
const none = { none: true } as const;
const act = (icon: string, label: Key, a: Action["act"] = none): Action => ({ icon, label: k(label), act: a });
const verb = (icon: string, label: Key, v: string): Action => act(icon, label, { verb: v });
/// A button that stands but cannot be pressed, saying why.
const off = (icon: string, label: Key, why: Key): Action => ({ ...act(icon, label), off: k(why) });
/// A copy of one of the item's secrets, done at once: a button is no place
/// for a preview of something this small.
const copyOf = (icon: string, label: Key, itemId: string, field: Exclude<SecretField, SecretField.Custom>): Action => act(icon, label, { copy: { itemId, field } });
/// A field's value that is no secret, from the opened item, when it has one.
const plainValue = (detail: ItemDetail | null, key: string): string | null => detail?.fields.find((f) => f.key === key && f.value)?.value ?? null;
/// The address a login's site opens at: its first URI that reads as one.
function siteUrl(uris: string[]): string | null {
  for (const u of uris) {
    const host = siteHost(u);
    if (!host) continue;
    return /^[a-z][a-z0-9+.-]*:/i.test(u) ? (/^https?:/i.test(u) ? u : null) : `https://${u}`;
  }
  return null;
}
const nodeLead = (id: string): Lead => ({ tile: LeadTile.Node, id });
/// A node's mark: loud levels say why, quiet ones say they are fine.
const stateMark = (n: Node): MarkSpec => (isLoud(n.level) ? mark(n.level, n.why ?? k(`level.${n.level}` as Key)) : mark(Level.Healthy, k("level.healthy")));
const loudMark = (n: Node): MarkSpec | undefined => (isLoud(n.level) ? mark(n.level, n.short ?? k(`level.${n.level}` as Key)) : undefined);
/// A ref to a node, the way a column row reads it.
const nodeRef = (dir: Directory, id: string, extra: Partial<Extract<Block, { ref: string | null }>> = {}): Block => {
  const n = dir.node(id);
  return { ref: id, lead: nodeLead(id), title: n.name, mono: n.mono ?? false, ...(n.sub ? { context: n.sub } : {}), ...(loudMark(n) ? { mark: loudMark(n)! } : {}), ...extra };
};
const sec = (title: Text, blocks: Block[], extra: Partial<Section> = {}): Section => ({ title, blocks, ...extra });
const levelCount = (levels: Level[]): Text | null => {
  const crit = levels.filter((l) => l === Level.Critical).length;
  const actn = levels.filter((l) => l === Level.Action).length;
  const warn = levels.filter((l) => l === Level.Warning).length;
  if (crit && actn) return k("state.both", { a: k("state.crit", { n: crit }), b: k("state.act", { n: actn }) });
  if (crit) return k("state.crit", { n: crit });
  if (actn) return k("state.act", { n: actn });
  if (warn) return k("state.warn", { n: warn });
  return null;
};
const summary = (n: Node, levels: Level[]): MarkSpec => {
  const t = levelCount(levels);
  return t && isLoud(n.level) ? mark(n.level, t) : mark(Level.Healthy, k("why.none"));
};

export function buildDoc(ctx: DocContext, id: string): DocSpec {
  const n = ctx.dir.node(id);
  if (n.doc) return n.doc(ctx.dir);
  switch (n.kind) {
    case NodeKind.Root:
    case NodeKind.All:
      return home(ctx);
    case NodeKind.Personal:
      return personal(ctx);
    case NodeKind.Folder:
      return folder(ctx, n);
    case NodeKind.Org:
      return org(ctx, n);
    case NodeKind.Collection:
      return collection(ctx, n);
    case NodeKind.Member:
      return member(ctx, n);
    case NodeKind.Item:
      return item(ctx, n);
    case NodeKind.Trash:
      return trash(ctx, n);
    case NodeKind.Section:
      if (id.endsWith("/collections")) return collections(ctx, n);
      if (id.endsWith("/members")) return members(ctx, n);
      if (id.endsWith("/policies")) return policies(ctx, n);
      return org(ctx, ctx.dir.node(ctx.dir.orgOf(id)!));
    case NodeKind.Plugin:
      throw new Error(`plugin node "${id}" brings no page of its own`);
    case NodeKind.Settings:
    case NodeKind.SettingsPage:
    case NodeKind.InstalledPlugin:
    case NodeKind.PluginOffer:
      throw new Error(`settings node "${id}" lost its page`);
  }
}

function home(ctx: DocContext): DocSpec {
  const { dir } = ctx;
  const root = dir.node("root");
  const live = dir.all().filter((x) => x.result && x.kind === NodeKind.Item);
  const urgent = dir.all().filter((x) => x.result && (x.level === Level.Critical || x.level === Level.Action) && x.item?.kind !== ItemKind.SshKey && x.kind !== NodeKind.Member);
  urgent.sort((a, b) => Number(b.kind === NodeKind.Item) - Number(a.kind === NodeKind.Item));
  const owners = dir.kidIds("root").filter((x) => [NodeKind.Personal, NodeKind.Org].includes(dir.node(x).kind));
  const plugins = dir.contributions.map((c) => c.root.id);
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "vault", hue: Hue.Sky },
      title: k("root"),
      place: [],
      what: k("home.what", { server: ctx.server, items: k("count.items", { n: live.length }) }),
      state: summary(root, live.map((x) => x.level)),
      primary: verb("plus", "doc.newItem", "new"),
      more: [act("refresh", "sync", { sync: true }), act("more", "doc.more", { menu: true })],
    },
    sections: [
      ...(urgent.length ? [sec(k("doc.firstThis"), urgent.map((x) => nodeRef(dir, x.id, x.why ? { mark: mark(x.level, x.short ?? x.why) } : {})), { count: urgent.length })] : []),
      sec(
        k("doc.owners"),
        owners.map((o) => {
          const on = dir.node(o);
          return { ref: o, lead: nodeLead(o), title: on.name, context: ownerContext(dir, on), mark: isLoud(on.level) ? mark(on.level, k(`level.${on.level}` as Key)) : mark(Level.Healthy, k("level.healthy")) };
        }),
      ),
      ...(plugins.length
        ? [
            sec(
              k("doc.connections"),
              plugins.map((p) => {
                const pn = dir.node(p);
                return { ref: p, lead: nodeLead(p), title: pn.name, ...(pn.sub ? { context: pn.sub } : {}), mark: isLoud(pn.level) ? mark(pn.level, pn.short ?? pn.why ?? k(`level.${pn.level}` as Key)) : mark(Level.Healthy, k("level.healthy")) };
              }),
            ),
          ]
        : []),
      ...(ctx.places.length
        ? [
            sec(
              k("places"),
              ctx.places.map((p): Block => ({ ref: null, lead: p.level ? { tile: LeadTile.Glyph, level: p.level } : { tile: LeadTile.Plain, icon: p.icon! }, title: p.name, act: { run: p.line } })),
              { aside: { label: k("doc.savedQueries"), act: none } },
            ),
          ]
        : []),
    ],
  };
}

/// Who an owner is to the one looking: only them, or their role and how
/// many share it.
function ownerContext(dir: Directory, n: Node): Text {
  if (n.kind === NodeKind.Personal) return k("home.ownerPersonal", { folders: k("count.folders", { n: dir.catalog.folders.length }) });
  const o = dir.catalog.orgs.find((x) => `org:${x.id}` === n.id)!;
  const ms = dir.catalog.members.filter((m) => m.orgId === o.id).length;
  const you = k(`you.${o.role}` as Key);
  return ms ? k("home.ownerOrg", { you, members: k("count.members", { n: ms }) }) : you;
}

function personal(ctx: DocContext): DocSpec {
  const { dir } = ctx;
  const n = dir.node("personal");
  const items = dir.all().filter((x) => x.item && !x.item.deleted && !x.item.orgId);
  const loud = items.filter((x) => isLoud(x.level));
  const folders = dir.kidIds("personal").filter((x) => dir.node(x).kind === NodeKind.Folder);
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "person", hue: Hue.Sky },
      title: n.name,
      place: [],
      what: k("personal.sub", { n: items.length }),
      state: summary(n, items.map((x) => x.level)),
      primary: verb("plus", "doc.newItem", "new"),
      more: [verb("folder", "doc.newFolder", "new folder"), act("more", "doc.more", { menu: true })],
    },
    sections: [
      ...(loud.length ? [sec(k("doc.firstThis"), loud.map((x) => nodeRef(dir, x.id)))] : []),
      sec(
        k("doc.folders"),
        folders.map((f) => {
          const fn = dir.node(f);
          return { ref: f, lead: { tile: LeadTile.Plain, icon: "folder" }, title: fn.name, context: k("count.items", { n: fn.count ?? 0 }), mark: stateMark(fn).level === Level.Healthy ? mark(Level.Healthy, k("level.healthy")) : mark(fn.level, k(`level.${fn.level}` as Key)) };
        }),
      ),
    ],
  };
}

function folder(ctx: DocContext, n: Node): DocSpec {
  const ids = ctx.dir.kidIds(n.id);
  const loud = ids.filter((x) => isLoud(ctx.dir.node(x).level)).length;
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "folder", hue: Hue.Dim },
      title: n.name,
      place: n.home.slice(0, -1),
      what: k("doc.folder"),
      state: loud ? mark(n.level, k("state.needAttention", { n: loud })) : mark(Level.Healthy, k("why.none")),
      primary: verb("plus", "doc.newItem", "new"),
      more: [verb("edit", "doc.rename", "rename"), verb("trash", "verb.folder.delete", "delete")],
    },
    sections: [sec(k("doc.items"), ids.map((x) => nodeRef(ctx.dir, x)), { count: ids.length })],
  };
}

const roleKey = (r: string) => `role.${r}` as Key;

function org(ctx: DocContext, n: Node): DocSpec {
  const { dir } = ctx;
  const o = dir.catalog.orgs.find((x) => `org:${x.id}` === n.id)!;
  const ms = dir.catalog.members.filter((m) => m.orgId === o.id);
  const cs = dir.catalog.collections.filter((c) => c.orgId === o.id);
  const hasMembers = dir.has(`${n.id}/members`);
  // Members a backend is still reading: the table stands as on its way.
  const membersComing = !hasMembers && !!dir.catalog.membersLoading && o.can.manageMembers;
  const finds = orgFindings(dir, n.id).filter((f) => f.doc);
  const levels = finds.map((f) => f.level);
  const pending = ms.filter((m) => m.status !== MemberStatus.Confirmed);
  const can = o.can;
  const collRef = (cid: string): Block => {
    const c = dir.node(`collection:${cid}`);
    const seers = ms.filter((m) => m.accessAll || m.access[cid]).length;
    const ctxText = hasMembers ? k("doc.collSeen", { items: k("count.items", { n: c.count ?? 0 }), members: k("count.members", { n: seers }) }) : k("count.items", { n: c.count ?? 0 });
    const own = cs.find((x) => x.id === cid)!;
    return {
      ref: c.id,
      lead: { tile: LeadTile.Plain, icon: "stack" },
      title: c.name,
      context: ctxText,
      ...(hasMembers ? { mark: isLoud(c.level) ? mark(c.level, k(`level.${c.level}` as Key)) : mark(Level.Healthy, k("level.healthy")) } : { perm: k(own.readOnly ? "perm.read" : "perm.edit") }),
    };
  };
  const sections: Section[] = [];
  if (finds.length)
    sections.push(
      sec(
        k("doc.firstThis"),
        finds.map(
          (f): Block => ({
            sig: f.level,
            title: f.title,
            sub: f.sub,
            action: { label: k(f.action.label), act: "map" in f.action.act ? { map: { kind: MapKind.Access, anchor: n.id } } : f.action.act },
          }),
        ),
      ),
    );
  if (hasMembers) {
    sections.push(sec(k("section.members"), [{ members: ms }], { count: ms.length, aside: { label: k("doc.all"), act: { go: `${n.id}/members` } } }));
    if (pending.length)
      sections.push(
        sec(
          k("doc.pending"),
          pending.map(
            (m): Block =>
              m.status === MemberStatus.Accepted
                ? { sig: Level.Action, title: k("doc.acceptedInvite", { name: m.name ?? m.email }), sub: k("doc.confirmKey"), action: { label: k("doc.confirm"), act: verbOn(dir, `member:${m.id}`, "confirm") } }
                : { sig: Level.Unknown, title: k("doc.noReply", { name: m.name ?? m.email }), sub: { raw: m.email }, action: { label: k("doc.resend"), act: { go: `member:${m.id}` } } },
          ),
          { count: pending.length },
        ),
      );
  } else if (membersComing) sections.push(sec(k("section.members"), [{ skeleton: SkeletonKind.Members, rows: 4, words: k("load.members") }]));
  sections.push(sec(k("section.collections"), cs.map((c) => collRef(c.id)), { count: cs.length }));
  if (hasMembers) sections.push(sec(k("doc.access"), [{ mapdoor: { kind: MapKind.Access, anchor: n.id }, title: k("access.sub"), sub: k("doc.accessDoor") }]));
  return {
    hero: {
      lead: { tile: LeadTile.Letter, of: o.name, hue: n.hue ?? Hue.Orange },
      title: n.name,
      place: [],
      what: k("doc.orgWhat", { you: k(`you.${o.role}` as Key) }),
      state: hasMembers ? summary(n, levels) : stateMark(n),
      ...(can.manageMembers ? { primary: verb("mail", "doc.invite", "invite") } : {}),
      more: [
        ...(hasMembers ? [act("map", "map.access", { map: { kind: MapKind.Access, anchor: n.id } })] : []),
        ...(can.editOrg ? [verb("check", "verb.require2fa", "require 2fa")] : []),
        ...(newCollection(n) ? [newCollection(n)!] : []),
        act("more", "doc.more", { menu: true }),
      ],
    },
    sections,
    ...(hasMembers || membersComing ? { wide: true } : { note: k("doc.adminsOnly", { org: n.name }) }),
  };
}

function collections(ctx: DocContext, n: Node): DocSpec {
  const { dir } = ctx;
  const ids = dir.kidIds(n.id);
  const items = ids.flatMap((c) => dir.kidIds(c));
  const loud = items.map((x) => dir.node(x)).filter((x) => isLoud(x.level));
  const ms = dir.catalog.members.filter((m) => `org:${m.orgId}` === dir.orgOf(n.id));
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "stack", hue: Hue.Orange },
      title: n.name,
      place: n.home.slice(0, -1),
      what: k("doc.collsWhat", { colls: k("count.collections", { n: ids.length }), items: k("count.items", { n: items.length }) }),
      state: loud.length ? mark(loud[0]!.level, k("why.of", { name: loud[0]!.name, why: loud[0]!.why! })) : mark(Level.Healthy, k("why.none")),
      ...(newCollection(n) ? { primary: { ...newCollection(n)!, icon: "plus" } } : {}),
    },
    sections: [
      sec(
        n.name,
        ids.map((c) => {
          const cn = dir.node(c);
          const cid = c.slice("collection:".length);
          const seers = ms.filter((m) => m.accessAll || m.access[cid]).length;
          return { ref: c, lead: { tile: LeadTile.Plain, icon: "stack" }, title: cn.name, context: k("doc.collSeenBy", { items: k("count.items", { n: cn.count ?? 0 }), members: k("count.members", { n: seers }) }), mark: isLoud(cn.level) ? mark(cn.level, k(`level.${cn.level}` as Key)) : mark(Level.Healthy, k("level.healthy")) };
        }),
      ),
    ],
  };
}

const permLong: Record<string, Key> = { manage: "perm.long.manage", edit: "perm.long.edit", editHidden: "perm.long.editHidden", read: "perm.long.read", readHidden: "perm.long.readHidden" };

function collection(ctx: DocContext, n: Node): DocSpec {
  const { dir } = ctx;
  const cid = n.id.slice("collection:".length);
  const orgId = dir.orgOf(n.id)!;
  const ids = dir.kidIds(n.id);
  const ms = dir.catalog.members.filter((m) => `org:${m.orgId}` === orgId);
  const has = ms.filter((m) => m.accessAll || m.access[cid]);
  const without = ms.filter((m) => !has.includes(m));
  const loud = ids.map((x) => dir.node(x)).filter((x) => isLoud(x.level));
  const memberRow = (m: Member, off = false): Block => {
    const mn = dir.node(`member:${m.id}`);
    const perm = m.accessAll ? Permission.Manage : m.access[cid];
    return {
      ref: mn.id,
      lead: nodeLead(mn.id),
      title: mn.name,
      context: k(roleKey(m.role)),
      ...(off ? { off: true } : { perm: k(permLong[perm!]!) }),
      ...(!off && isLoud(mn.level) ? { glyph: mark(mn.level, mn.why!) } : {}),
    };
  };
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "stack", hue: Hue.Orange },
      title: n.name,
      place: n.home.slice(0, -1),
      what: ms.length ? k("doc.collWhat", { a: has.length, b: ms.length }) : k("doc.collection"),
      state: loud.length ? mark(n.level, loud.length === 1 ? loud[0]!.why! : k("state.needAttention", { n: loud.length })) : mark(Level.Healthy, k("why.none")),
      ...(ms.length ? { primary: act("people", "doc.changeAccess", { map: { kind: MapKind.Access, anchor: orgId } }) } : {}),
      more: [verb("plus", "doc.newItem", "new"), ...collectionActions(n), act("more", "doc.more", { menu: true })],
    },
    sections: [
      sec(k("doc.items"), ids.map((x) => nodeRef(dir, x)), { count: ids.length }),
      ...(ms.length ? [sec(k("doc.whoHasAccess"), has.map((m) => memberRow(m)), { count: has.length })] : []),
      ...(without.length ? [sec(k("doc.noAccess"), without.map((m) => memberRow(m, true)), { count: without.length })] : []),
    ],
  };
}

function members(ctx: DocContext, n: Node): DocSpec {
  const { dir } = ctx;
  const orgId = dir.orgOf(n.id)!;
  const ms = dir.catalog.members.filter((m) => `org:${m.orgId}` === orgId);
  const on = ms.filter((m) => m.twoFactor === true).length;
  const off = ms.filter((m) => m.twoFactor === false).length;
  const unk = ms.filter((m) => m.twoFactor === null).length;
  const accepted = ms.filter((m) => m.status === MemberStatus.Accepted).length;
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "people", hue: Hue.Orange },
      title: n.name,
      place: n.home.slice(0, -1),
      what: k("count.members", { n: ms.length }),
      state: accepted ? mark(Level.Action, k("state.awaitConfirm", { n: accepted })) : stateMark(n),
      ...(invite(n) ? { primary: invite(n)! } : {}),
      more: [act("map", "map.access", { map: { kind: MapKind.Access, anchor: orgId } }), verb("check", "verb.require2fa", "require 2fa"), act("more", "doc.more", { menu: true })],
    },
    sections: [
      sec(k("doc.twoStep"), [
        {
          marks: [
            ...(on ? [mark(Level.Healthy, k("doc.tfaOn", { n: on }))] : []),
            ...(off ? [mark(Level.Warning, k("doc.tfaOff", { n: off }))] : []),
            ...(unk ? [mark(Level.Unknown, k("doc.tfaUnknown", { n: unk }))] : []),
          ],
        },
      ]),
      sec(k("doc.all"), [{ members: ms }], { count: ms.length }),
    ],
    wide: true,
  };
}

function member(ctx: DocContext, n: Node): DocSpec {
  const { dir } = ctx;
  const m = n.member!;
  const orgId = dir.orgOf(n.id)!;
  const reach = dir.reach(m);
  const can = reach.filter((r) => r.perm);
  const closed = reach.filter((r) => !r.perm);
  const items = can.flatMap((r) => dir.kidIds(`collection:${r.collection}`));
  const flagged = items.filter((x) => isLoud(dir.node(x).level)).length;
  const ms = dir.catalog.members.filter((x) => `org:${x.orgId}` === orgId);
  const status: MarkSpec =
    m.status === MemberStatus.Confirmed ? mark(Level.Healthy, k("status.confirmed")) : m.status === MemberStatus.Accepted ? mark(Level.Action, k("status.acceptedAwaits")) : mark(Level.Unknown, k(`status.${m.status}` as Key));
  const tfa: MarkSpec = m.twoFactor === null ? mark(Level.Unknown, k("doc.unknown")) : m.twoFactor ? mark(Level.Healthy, k("doc.on")) : mark(Level.Warning, k("doc.off"));
  return {
    hero: {
      lead: { tile: LeadTile.Avatar, of: m.name ?? m.email, hue: Hue.Orange },
      title: n.name,
      place: n.home.slice(0, -1),
      what: k(roleKey(m.role)),
      state: mark(n.level, n.why!),
      ...(memberActions(n).primary ? { primary: memberActions(n).primary! } : {}),
      more: [act("map", "map.access", { map: { kind: MapKind.Access, anchor: orgId } }), ...memberActions(n).more, act("mail", "doc.write", { open: `mailto:${m.email}` }), act("more", "doc.more", { menu: true })],
    },
    sections: [
      sec(k("doc.access"), [
        {
          marks: [
            mark(Level.Healthy, k("doc.reachOpen", { a: can.length, b: reach.length })),
            ...(closed.length ? [mark(Level.Unknown, k("doc.reachClosed", { n: closed.length }))] : []),
            ...(flagged ? [mark(Level.Warning, k("doc.reachFlagged", { n: flagged }))] : []),
          ],
        },
      ]),
      sec(
        k("doc.whatTheyReach"),
        can.flatMap((r): Block[] => {
          const cn = dir.node(`collection:${r.collection}`);
          return [
            { ref: cn.id, lead: { tile: LeadTile.Plain, icon: "stack" }, title: cn.name, context: k("count.items", { n: cn.count ?? 0 }), perm: k(permLong[r.perm!]!) },
            ...dir.kidIds(cn.id).map((x) => nodeRef(dir, x, { nest: true })),
          ];
        }),
        { count: k("count.items", { n: items.length }) },
      ),
      ...(closed.length
        ? [
            sec(
              k("doc.outOfReach"),
              closed.map((r): Block => {
                const cn = dir.node(`collection:${r.collection}`);
                const seers = ms.filter((x) => x.accessAll || x.access[r.collection]).length;
                return { ref: cn.id, lead: { tile: LeadTile.Plain, icon: "lock" }, title: cn.name, context: k("doc.collSeenBy", { items: k("count.items", { n: cn.count ?? 0 }), members: k("count.members", { n: seers }) }), mark: mark(Level.Unknown, k("perm.closed")), off: true };
              }),
              { count: closed.length },
            ),
          ]
        : []),
      sec(k("kind.member"), [
        { field: k("field.email"), value: { raw: m.email }, mono: true },
        { field: k("doc.role"), value: k(roleKey(m.role)) },
        { field: k("doc.status"), value: { raw: "" }, mark: status },
        { field: k("doc.twoStep"), value: { raw: "" }, mark: tfa },
        { field: k("doc.accessAll"), value: k(m.accessAll ? "doc.accessAllYes" : "doc.accessAllNo") },
      ]),
    ],
  };
}

const POLICY: Record<Policy["type"], Key> = {
  [PolicyType.MasterPassword]: "policy.masterPassword",
  [PolicyType.TwoFactor]: "policy.twoFactor",
  [PolicyType.SingleOrg]: "policy.singleOrg",
  [PolicyType.ResetPassword]: "policy.resetPassword",
  [PolicyType.PersonalOwnership]: "policy.personalOwnership",
  [PolicyType.VaultTimeout]: "policy.vaultTimeout",
};
function policyWords(p: Policy, offCount: number): Text {
  switch (p.type) {
    case PolicyType.MasterPassword:
      return p.enabled ? k("policy.masterPassword.on", { n: Number(p.data.minLength ?? 0) }) : k("policy.off");
    case PolicyType.TwoFactor:
      return p.enabled ? k("policy.twoFactor.on") : k("policy.twoFactor.off", { n: offCount });
    case PolicyType.SingleOrg:
      return k(p.enabled ? "policy.singleOrg.on" : "policy.off");
    case PolicyType.ResetPassword:
      return k(p.enabled ? "policy.resetPassword.on" : "policy.off");
    case PolicyType.PersonalOwnership:
      return k(p.enabled ? "policy.personalOwnership.on" : "policy.personalOwnership.off");
    case PolicyType.VaultTimeout:
      return p.enabled ? k(policyLevel(p) === Level.Warning ? "policy.vaultTimeout.long" : "policy.vaultTimeout.on", { n: Math.round(Number(p.data.minutes ?? 0) / 60) }) : k("policy.off");
  }
}

function policies(ctx: DocContext, n: Node): DocSpec {
  const { dir } = ctx;
  const orgId = dir.orgOf(n.id)!;
  const ps = (dir.catalog.policies ?? []).filter((p) => `org:${p.orgId}` === orgId);
  const off = dir.catalog.members.filter((m) => `org:${m.orgId}` === orgId && m.twoFactor === false).length;
  const tf = ps.find((p) => p.type === PolicyType.TwoFactor && policyLevel(p) !== Level.Healthy);
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "policy", hue: Hue.Orange },
      title: n.name,
      place: n.home.slice(0, -1),
      state: tf ? mark(policyLevel(tf), k("find.twoFactorOptional")) : stateMark(n),
      ...(tf ? { primary: verb("check", "policy.require", "require 2fa") } : {}),
      more: [act("more", "doc.more", { menu: true })],
    },
    sections: [
      sec(
        n.name,
        ps.map((p): Block => {
          const lv = policyLevel(p);
          return {
            sig: lv,
            title: k(POLICY[p.type]),
            sub: policyWords(p, off),
            ...(p.type === PolicyType.TwoFactor && lv !== Level.Healthy ? { action: { label: k("find.require"), act: { verb: "require 2fa" } } } : lv !== Level.Healthy ? { action: { label: k("doc.change"), act: none } } : {}),
          };
        }),
        { count: ps.length },
      ),
    ],
  };
}

function trash(ctx: DocContext, n: Node): DocSpec {
  const ids = ctx.dir.kidIds(n.id);
  return {
    hero: { lead: { tile: LeadTile.Icon, icon: "trash", hue: Hue.Dim }, title: n.name, place: [], what: k("count.items", { n: ids.length }), state: mark(Level.Unknown, k("trash.state")) },
    sections: [sec(k("doc.items"), ids.map((x) => nodeRef(ctx.dir, x, { act: { verb: "restore" } })), { count: ids.length })],
  };
}

const FIELD_KEY: Record<string, Key> = {
  username: "field.username",
  password: "field.password",
  totp: "field.totp",
  cardholder: "field.cardholder",
  brand: "field.brand",
  expiry: "field.expiry",
  cardNumber: "field.cardNumber",
  cardCode: "field.cardCode",
  fullName: "field.fullName",
  email: "field.email",
  phone: "field.phone",
  fingerprint: "field.fingerprint",
  publicKey: "field.publicKey",
  privateKey: "field.privateKey",
  notes: "field.notes",
  algorithm: "field.algorithm",
  company: "field.company",
  passport: "field.passport",
};
/// A field's label: a built-in key translated, a name a person made up as it
/// is. A built-in key the window does not know is an error, not a raw word.
export function fieldLabel(f: Field): Text {
  if (f.key === null || isCustomKind(f.key)) return { raw: f.label };
  const key = FIELD_KEY[f.key];
  if (!key) throw new Error(`no words for the field "${f.key}"`);
  return { key };
}
/// The verb a field's copy button opens.
const COPY_VERB: Record<string, string> = { username: "copy username", password: "copy password", totp: "copy totp", cardNumber: "copy number" };

/// How many fields an item of a kind shows, near enough: the rows its
/// skeleton stands with while the item is read.
const SKELETON_ROWS: Record<ItemKind, number> = {
  [ItemKind.Login]: 4,
  [ItemKind.Card]: 4,
  [ItemKind.Identity]: 5,
  [ItemKind.SecureNote]: 1,
  [ItemKind.SshKey]: 3,
};

function fieldBlocks(it: NonNullable<Node["item"]>, detail: ItemDetail | null): Block[] {
  if (!detail) return [{ skeleton: SkeletonKind.Fields, rows: SKELETON_ROWS[it.kind] }];
  if (detail.item.id !== it.id) throw new Error(`the opened item is "${detail.item.id}", the page is "${it.id}"`);
  const out: Block[] = [];
  for (const f of detail.fields) {
    if (f.key === "totp") {
      out.push({ totp: it.id, verb: COPY_VERB.totp! });
      continue;
    }
    if (f.key === "privateKey") {
      // The private key is never shown or copied: it signs in the daemon.
      out.push({ field: fieldLabel(f), value: k("doc.privateKey"), dim: true });
      continue;
    }
    const custom = customValue(f);
    if (custom) {
      out.push({ field: fieldLabel(f), value: custom });
      continue;
    }
    if (f.value === null) {
      if (!f.secret) throw new Error(`the field "${f.label}" has neither a value nor a reference`);
      // A card's last four digits are on its row already; the dots end with them.
      const tail = f.key === "cardNumber" ? /(\d{4})$/.exec(it.subtitle ?? "")?.[1] : undefined;
      out.push({ secret: f, itemId: it.id, ...(f.key && COPY_VERB[f.key] ? { verb: COPY_VERB[f.key]! } : {}), ...(tail ? { tail } : {}) });
      continue;
    }
    out.push({ field: fieldLabel(f), value: { raw: f.value }, mono: f.mono, ...(f.secret ? { copy: f.key && COPY_VERB[f.key] ? { verb: COPY_VERB[f.key]! } : { copy: f.secret } } : {}) });
  }
  if (it.kind === ItemKind.Login && !it.hasTotp) out.splice(Math.min(out.length, 2), 0, { field: k("field.totp"), value: { raw: "" }, mark: mark(Level.Warning, k("doc.notSetUp")) });
  if (it.kind === ItemKind.Login && it.uris[0]) {
    const host = siteHost(it.uris[0]);
    out.push({ field: k("field.site"), value: { raw: host ?? it.uris[0] }, mono: true, ...(host ? { open: true } : {}) });
  }
  return out;
}

function item(ctx: DocContext, n: Node): DocSpec {
  const { dir } = ctx;
  const it = n.item!;
  const relMap = act("map", "map.relations", { map: { kind: MapKind.Relations, anchor: n.id } });
  let primary: Action | undefined;
  let more: Action[] = [];
  let body: Section | null = null;
  let security: Block[] = [];
  const fields = fieldBlocks(it, ctx.detail);
  // A copy of the same record is told apart from a password shared with
  // another one: the first is housekeeping, the second a risk.
  const partners = reusedWith(it, dir.catalog);
  const copies = duplicatesOf(it, dir.catalog);
  const links = dir.links().filter((l) => l.to === n.id && dir.has(l.from));
  if (it.deleted) {
    primary = verb("refresh", "verb.restore", "restore");
    body = sec(k("doc.contents"), fields);
  } else if (it.kind === ItemKind.Login) {
    primary = copyOf("copy", "doc.copyPassword", it.id, SecretField.Password);
    const site = siteUrl(it.uris);
    more = [
      copyOf("user2", "verb.copyUsername", it.id, SecretField.Username),
      ...(it.hasTotp ? [copyOf("hash", "verb.copyTotp", it.id, SecretField.Totp)] : []),
      verb("refresh", "verb.rotate", "rotate"),
      site ? act("ext", "doc.openSite", { open: site }) : off("ext", "doc.openSite", "doc.noSite"),
      relMap,
      verb("edit", "doc.edit", "edit"),
    ];
    body = sec(k("doc.signIn"), fields);
    const months = it.passwordRevised ? Math.floor((dir.now.getTime() - Date.parse(it.passwordRevised)) / (30 * 86_400_000)) : null;
    security = [
      // One finding for all the copies, and one way out of it: the copies
      // themselves are among the relations.
      ...(copies.length
        ? [{ sig: Level.Warning, title: k("doc.duplicate"), sub: copies.length === 1 ? k("doc.duplicateSub", { place: itemPlace(copies[0]!, dir.catalog) }) : k("why.duplicates", { n: copies.length }), action: { label: k("verb.merge"), act: { verb: "merge" } } }]
        : []),
      ...(partners.length
        ? [{ sig: Level.Critical, title: k("doc.reused"), sub: partners.length === 1 ? k("doc.sameAs", { name: partnerName(partners[0]!, it, dir.catalog) }) : k("why.reused", { n: partners.length }), action: { label: k("doc.change"), act: { verb: "rotate" } } }]
        : copies.length
          ? []
          : [{ sig: Level.Healthy, title: k("doc.unique"), sub: k("doc.uniqueSub") }]),
      it.hasTotp ? { sig: Level.Healthy, title: k("doc.twoStep"), sub: k("doc.totpHere") } : { sig: Level.Warning, title: k("doc.noTwoStep"), sub: k("doc.noTwoStepSub") },
      ...(months !== null
        ? [months > 12 ? { sig: Level.Warning, title: k("doc.oldPassword"), sub: k("doc.changedAgo", { ago: ago(it.passwordRevised!, dir.now) }) } : { sig: Level.Healthy, title: k("doc.passwordAge"), sub: k("doc.changedAgo", { ago: ago(it.passwordRevised!, dir.now) }) }]
        : []),
    ];
  } else if (it.kind === ItemKind.Card) {
    primary = copyOf("copy", "doc.copyNumber", it.id, SecretField.CardNumber);
    more = [it.expires ? act("clock", "doc.copyExpiry", { copyText: { text: expiryText(it.expires).replace(/ /g, ""), what: k("doc.expiry") } }) : off("clock", "doc.copyExpiry", "doc.noExpiry"), relMap, verb("edit", "doc.edit", "edit")];
    body = sec(k("kind.card"), fields);
    security = [
      { sig: isLoud(n.level) && it.expires ? n.level : Level.Healthy, title: isLoud(n.level) ? n.why! : k("doc.expiryFine"), sub: it.expires ? k("doc.expiryIs", { date: expiryText(it.expires).replace(/ /g, "") }) : k("doc.noExpiry") },
      it.reprompt ? { sig: Level.Healthy, title: k("doc.reprompt"), sub: k("doc.repromptOn") } : { sig: Level.Unknown, title: k("doc.noReprompt"), sub: k("doc.noRepromptSub") },
    ];
  } else if (it.kind === ItemKind.SecureNote) {
    primary = act("eye", "doc.openNote", { reveal: true });
    more = [verb("edit", "doc.edit", "edit")];
    body = sec(k("doc.contents"), detailNotes(it.id, ctx.detail));
    security = [{ sig: Level.Unknown, title: k("doc.notChecked"), sub: k("doc.notCheckedSub") }];
  } else if (it.kind === ItemKind.Identity) {
    const email = plainValue(ctx.detail, "email");
    primary = email ? act("copy", "doc.copyEmail", { copyText: { text: email, what: k("field.email") } }) : off("copy", "doc.copyEmail", ctx.detail ? "doc.noEmail" : "doc.reading");
    more = [verb("edit", "doc.edit", "edit")];
    body = sec(k("kind.identity"), fields);
    security = [{ sig: Level.Healthy, title: k("why.none") }];
  } else {
    // A key opens no shell of its own: the hosts it signs in to do.
    const host = links[0];
    if (host) primary = act("terminal", "doc.openHost", { go: host.from });
    const publicKey = plainValue(ctx.detail, "publicKey");
    more = [publicKey ? act("copy", "doc.copyPublicKey", { copyText: { text: publicKey, what: k("field.publicKey") } }) : off("copy", "doc.copyPublicKey", ctx.detail ? "doc.noPublicKey" : "doc.reading"), relMap, verb("edit", "doc.edit", "edit")];
    body = sec(k("doc.key"), fields);
    security = links.map((l): Block => {
      const h = dir.node(l.from);
      return { sig: l.level === Level.Critical ? Level.Critical : l.level === Level.Warning ? Level.Warning : Level.Healthy, title: h.name, mono: h.mono ?? false, sub: l.words, go: { go: h.id } };
    });
  }
  const rel: Block[] = [];
  for (const c of copies) rel.push({ ref: `item:${c.id}`, lead: nodeLead(`item:${c.id}`), title: { raw: c.name }, context: k("doc.copyAt", { place: itemPlace(c, dir.catalog) }), mark: mark(Level.Warning, k("short.duplicate")) });
  for (const p of partners) rel.push({ ref: `item:${p.id}`, lead: nodeLead(`item:${p.id}`), title: { raw: p.name }, context: k("map.samePassword"), mark: mark(Level.Critical, k("short.reused")) });
  for (const s of sameService(it, dir.catalog)) {
    const sn = dir.node(`item:${s.id}`);
    rel.push({ ref: sn.id, lead: nodeLead(sn.id), title: sn.name, context: k("doc.sameServiceAt", { place: placeOf(dir, sn) }) });
  }
  if (it.kind !== ItemKind.SshKey)
    for (const l of links) {
      const from = dir.node(l.from);
      rel.push({ ref: from.id, lead: { tile: LeadTile.Plain, icon: from.icon }, title: from.name, mono: from.mono ?? false, context: l.words, ...(l.level ? { mark: mark(l.level, l.short) } : {}) });
    }
  if (it.orgId && it.collectionIds[0]) {
    const cid = it.collectionIds[0];
    const seers = dir.catalog.members.filter((m) => m.orgId === it.orgId && (m.accessAll || m.access[cid])).length;
    if (dir.has(`org:${it.orgId}/members`)) rel.push({ ref: `collection:${cid}`, lead: { tile: LeadTile.Plain, icon: "people" }, title: k("count.members", { n: seers }), context: k("doc.seeThrough", { coll: dir.node(`collection:${cid}`).name }) });
  } else if (!it.orgId) rel.push({ ref: null, lead: { tile: LeadTile.Plain, icon: "lock" }, title: k("doc.onlyYou"), context: k("doc.neverShared") });
  const state: MarkSpec = { level: n.level, text: n.why! };
  return {
    hero: { lead: nodeLead(n.id), title: n.name, place: n.home.slice(0, -1), what: k(`kind.${it.kind}` as Key), state, primary, more: [...more, act("more", "doc.more", { menu: true })] },
    sections: [
      ...(body && body.blocks.length ? [body] : body ? [{ ...body, blocks: [] }] : []),
      sec(k(it.kind === ItemKind.SshKey ? "doc.opens" : "doc.security"), security),
      ...(rel.length ? [sec(k("doc.relations"), rel, { count: rel.length, aside: { label: k("map.relations"), act: { map: { kind: MapKind.Relations, anchor: n.id } }, icon: "map" } })] : []),
    ],
    ...(it.revised ? { history: k("doc.changedAgo", { ago: ago(it.revised, dir.now) }) } : {}),
  };
}

function detailNotes(itemId: string, d: ItemDetail | null): Block[] {
  if (!d) return [{ skeleton: SkeletonKind.Fields, rows: SKELETON_ROWS[ItemKind.SecureNote] }];
  if (!d.notes) return [{ para: k("doc.noNotes") }];
  return [{ secret: { key: "notes", label: "notes", value: null, secret: d.notes, mono: false }, itemId }];
}

/// "Acme › Collections › Finance": where a node lives, as one text.
function placeOf(dir: Directory, n: Node): Text {
  const ids = n.home.slice(0, -1);
  return ids.slice(1).reduce<Text>((acc, id) => ({ key: "map.placeJoin", args: { a: acc, b: dir.node(id).name } }), ids.length ? dir.node(ids[0]!).name : { key: "root" });
}
