// The core's verbs: what a line can end with in every app. Each says what it
// works on and what it will do; a plugin adds its own the same way. Pure.
import { siteHost } from "../model/fields";
import type { Key, Text } from "../i18n";
import { type Lead, LeadTile } from "../doc/spec";
import { reusePartners } from "../model/reasons";
import { isLoud, type Directory, type Node, NodeKind } from "../path/directory";
import type { Verb } from "../path/query";
import { type Delta, type Line, type Preview, PreviewKind } from "./spec";
import { type SecretRef, ItemKind, Level, SecretField } from "../model/types";
import { ORG_VERBS } from "./org";
import { EdgeKind } from "../map/types";

const k = (key: Key, args?: Record<string, string | number | Text>): Text => (args ? { key, args } : { key });
const login = (n: Node | null) => n?.item?.kind === ItemKind.Login && !n.item.deleted;
const inOrg = (n: Node | null) => !!n && n.home[0]?.startsWith("org:") === true && [NodeKind.Org, NodeKind.Section, NodeKind.Member, NodeKind.Collection].includes(n.kind);
const nodeLead = (id: string): Lead => ({ tile: LeadTile.Node, id });
const firstLogin = (dir: Directory) => dir.all().find((n) => login(n))?.id ?? null;
const firstOrg = (dir: Directory) => dir.all().find((n) => n.kind === NodeKind.Org && dir.has(`${n.id}/members`))?.id ?? null;
/// A URI's host, or none: a Bitwarden URI is free text, not always an address.
const hostOf = (uri: string | undefined) => (uri ? siteHost(uri) : null);

function rotate(dir: Directory, obj: string): Preview {
  const n = dir.node(obj);
  const it = n.item!;
  const others = reusePartners(it, dir.catalog);
  const site = hostOf(it.uris[0]);
  const rows: Delta[] = [
    { lead: nodeLead(obj), name: n.name, from: { level: n.level, text: k(others.length ? "short.reused" : "short.oldPassword") }, to: { level: Level.Healthy, text: k("verb.unique") } },
    ...others.map((o): Delta => {
      const on = dir.node(`item:${o.id}`);
      return { lead: nodeLead(on.id), name: on.name, from: { level: on.level, text: k("short.reused") }, to: { level: Level.Healthy, text: k("verb.unique") } };
    }),
  ];
  const stays: Line[] = [
    { level: Level.Healthy, title: k("verb.rotate.staysLogin"), sub: k("verb.rotate.staysLoginSub") },
    ...dir
      .links()
      .filter((l) => l.to === obj && l.kind === EdgeKind.Token && dir.has(l.from))
      .map((l): Line => ({ level: Level.Healthy, title: dir.node(l.from).name, sub: k("verb.rotate.staysToken") })),
  ];
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: k("verb.rotate"),
    lede: k("verb.rotate.lede"),
    steps: [
      { title: k("verb.rotate.s1"), sub: k("verb.rotate.s1sub") },
      { title: k("verb.rotate.s2"), sub: site ? k("verb.rotate.s2sub", { site }) : k("verb.rotate.s2subNoSite") },
      { title: k("verb.rotate.s3"), sub: k("verb.rotate.s3sub") },
    ],
    changes: { rows },
    stays,
    go: k("verb.rotate"),
    note: k("verb.fingerprint"),
    effect: { none: true },
  };
}

function copy(what: SecretField.Password | SecretField.Totp | SecretField.Username | SecretField.CardNumber): (dir: Directory, obj: string) => Preview {
  const word: Record<typeof what, Key> = { [SecretField.Password]: "verb.copy.password", [SecretField.Totp]: "verb.copy.totp", [SecretField.Username]: "verb.copy.username", [SecretField.CardNumber]: "verb.copy.cardNumber" };
  return (dir, obj) => {
    const ref: SecretRef = { itemId: dir.node(obj).item!.id, field: what };
    return {
      kind: PreviewKind.Ready,
      target: obj,
      title: k("verb.copy.title", { what: k(word[what]) }),
      lede: k("verb.copy.lede"),
      steps: [
        { title: k("verb.copy.s1"), sub: k("verb.copy.s1sub") },
        { title: k("verb.copy.s2"), sub: k("verb.copy.s2sub", { what: k(word[what]) }) },
      ],
      stays: [{ level: Level.Healthy, title: k("verb.copy.staysItem"), sub: k("verb.copy.staysItemSub") }],
      go: k("verb.copy.go"),
      ...(what === SecretField.Username ? {} : { note: k("verb.fingerprint") }),
      effect: { copy: ref },
    };
  };
}

const orgOfNode = (dir: Directory, obj: string) => {
  const o = dir.orgOf(obj);
  if (!o) throw new Error(`"${obj}" is not in an organisation`);
  return o;
};

function require2fa(dir: Directory, obj: string): Preview {
  const org = orgOfNode(dir, obj);
  const ms = dir.catalog.members.filter((m) => `org:${m.orgId}` === org);
  const off = ms.filter((m) => m.twoFactor === false);
  const on = ms.filter((m) => m.twoFactor === true);
  return {
    kind: PreviewKind.Ready,
    target: org,
    title: k("verb.require2fa.title", { org: dir.node(org).name }),
    lede: k("verb.require2fa.lede", { org: dir.node(org).name }),
    steps: [
      { title: k("verb.require2fa.s1"), sub: k("verb.require2fa.s1sub") },
      { title: k("verb.require2fa.s2"), sub: k("verb.require2fa.s2sub") },
    ],
    changes: {
      rows: [
        ...off.map(
          (m): Delta => ({ lead: nodeLead(`member:${m.id}`), name: { raw: m.name ?? m.email }, from: { level: Level.Warning, text: k("map.noTwoFactor") }, to: { level: Level.Unknown, text: k("verb.require2fa.awaits") } }),
        ),
        { lead: { tile: LeadTile.Plain, icon: "policy" }, name: k("verb.require2fa.policy"), from: { level: Level.Action, text: k("verb.require2fa.optional") }, to: { level: Level.Healthy, text: k("verb.require2fa.required") } },
      ],
    },
    stays: [{ level: Level.Healthy, title: k("verb.require2fa.staysOn", { n: on.length }), sub: k("verb.require2fa.staysOnSub") }],
    go: k("verb.require2fa.go"),
    note: k("verb.reversible"),
    effect: { none: true },
  };
}

function lock(): Preview {
  return {
    kind: PreviewKind.Ready,
    target: null,
    title: k("verb.lock"),
    lede: k("verb.lock.lede"),
    steps: [],
    stays: [{ level: Level.Healthy, title: k("verb.lock.stays"), sub: k("verb.lock.staysSub") }],
    go: k("verb.lock.go"),
    effect: { lock: true },
  };
}

function trash(dir: Directory, obj: string): Preview {
  const n = dir.node(obj);
  const loud = isLoud(n.level);
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: k("verb.trash"),
    lede: k("verb.trash.lede"),
    steps: [
      { title: k("verb.trash.s1"), sub: k("verb.trash.s1sub") },
      { title: k("verb.trash.s2"), sub: k("verb.trash.s2sub") },
    ],
    changes: { rows: [{ lead: nodeLead(obj), name: n.name, from: loud ? { level: n.level, text: n.short ?? k("level.action") } : { faint: k("verb.trash.inVault") }, to: { faint: k("verb.trash.inTrash") } }] },
    go: k("verb.trash"),
    effect: { trash: [n.item!.id] },
  };
}

function restore(dir: Directory, obj: string): Preview {
  const n = dir.node(obj);
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: k("verb.restore"),
    lede: k("verb.restore.lede"),
    steps: [{ title: k("verb.restore.s1"), sub: k("verb.restore.s1sub") }],
    changes: { rows: [{ lead: nodeLead(obj), name: n.name, from: { faint: k("verb.trash.inTrash") }, to: { faint: k("verb.trash.inVault") } }] },
    go: k("verb.restore"),
    effect: { restore: [n.item!.id] },
  };
}

export const CORE_VERBS: Verb[] = [
  {
    id: "map",
    name: k("verb.map"),
    icon: "map",
    applies: (n) => !!n && n.kind !== NodeKind.Root && (n.kind === NodeKind.Item || n.home.some((h) => h.startsWith("org:")) || n.home[0]?.startsWith("plugin:") === true),
  },
  { id: "rotate", name: k("verb.rotate"), applies: login, preview: rotate, example: firstLogin },
  { id: "copy password", name: k("verb.copyPassword"), applies: login, preview: copy(SecretField.Password), example: firstLogin },
  { id: "copy totp", name: k("verb.copyTotp"), applies: (n) => !!n?.item?.hasTotp, preview: copy(SecretField.Totp), example: firstLogin },
  { id: "copy username", name: k("verb.copyUsername"), applies: login, preview: copy(SecretField.Username), example: firstLogin },
  { id: "copy number", name: k("verb.copyNumber"), applies: (n) => n?.item?.kind === ItemKind.Card, preview: copy(SecretField.CardNumber), example: (d) => d.all().find((n) => n.item?.kind === ItemKind.Card)?.id ?? null },
  ...ORG_VERBS,
  { id: "require 2fa", name: k("verb.require2fa"), applies: inOrg, preview: require2fa, example: firstOrg },
  { id: "trash", name: k("verb.trash"), applies: (n) => !!n?.item && !n.item.deleted, preview: trash },
  { id: "restore", name: k("verb.restore"), applies: (n) => !!n?.item?.deleted, preview: restore },
  { id: "lock", name: k("verb.lock"), applies: () => true, preview: lock },
];

/// What a line's verb will do: the verb's own preview, or a word that the
/// object does not fit, or that there is no such verb.
export function previewOf(dir: Directory, verbs: Verb[], verb: string, obj: string | null, arg: string): Preview {
  const v = verbs.find((x) => x.id === verb);
  if (!v) return { kind: PreviewKind.Unknown, verb, known: verbs.map((x) => x.name) };
  const n = obj ? dir.node(obj) : null;
  if (!v.applies(n) && obj && v.refuses) {
    const why = v.refuses(dir, obj);
    if (why) return why;
  }
  if (!v.applies(n) || !v.preview) {
    const ex = v.example?.(dir) ?? null;
    return { kind: PreviewKind.Pick, verb, name: v.name, obj, example: ex, exampleName: ex ? dir.node(ex).name : null };
  }
  return v.preview(dir, obj ?? "root", arg);
}
