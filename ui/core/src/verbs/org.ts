// Running an organisation, as verbs: inviting people, a member's role and
// access, confirming and removing a member, and making, renaming and deleting
// collections. Each preview says who gets what and what is lost before ↵,
// and its controls write the line's argument, so the line, the URL and the
// sheet are one state. A verb is offered only where the organisation's `can`
// allows it, and never where it would lock the one looking out: there the
// preview explains instead. Pure.
//
// The argument, after the verb:
//   invite  a@x.example b@x.example role:manager all:yes finance:hidden
//   role    role:admin all:no finance:none platform:edit
//   new collection / rename   the name, as typed
// A collection is named by its slug; a level is manage, edit, read, hidden
// (passwords hidden) or none.
import type { Arg, Key, Text } from "../i18n";
import { type Lead, LeadTile, Hue } from "../doc/spec";
import { type Directory, type Node, NodeKind } from "../path/directory";
import type { Verb } from "../path/query";
import { changesItems, hidesPasswords, type Collection, Level, type Member, type Org, OrgRole, Permission, MemberStatus } from "../model/types";
import { isEnumValue } from "../model/enum";
import type { Invite, Writes } from "../writes";
import { type Choice, type Delta, type DeltaSide, type FormGroup, type Input, type Line, type OrgWrite, type Preview, PreviewKind, OrgOp } from "./spec";

const k = (key: Key, args?: Record<string, Arg>): Text => (args ? { key, args } : { key });
const raw = (s: string): Text => ({ raw: s });
const nodeLead = (id: string): Lead => ({ tile: LeadTile.Node, id });
const COLL_LEAD: Lead = { tile: LeadTile.Plain, icon: "stack" };
const nameOf = (m: Member) => m.name ?? m.email;

// ---------- the organisation as the verbs read it ----------

const orgOf = (n: Node | null): Org | null => n?.org ?? null;
const membersOf = (dir: Directory, orgId: string) => dir.catalog.members.filter((m) => m.orgId === orgId);
const collsOf = (dir: Directory, orgId: string) => dir.catalog.collections.filter((c) => c.orgId === orgId);
const collSlug = (dir: Directory, c: Collection) => dir.node(`collection:${c.id}`).slug;
const confirmedOwners = (dir: Directory, orgId: string) => membersOf(dir, orgId).filter((m) => m.role === OrgRole.Owner && m.status === MemberStatus.Confirmed);
/// The one confirmed owner: without them nobody could run the organisation.
export const isLastOwner = (dir: Directory, m: Member) => m.role === OrgRole.Owner && m.status === MemberStatus.Confirmed && confirmedOwners(dir, m.orgId).length === 1;

/// What a level of access reaches, the way `Directory.reach` reads it.
const effective = (accessAll: boolean, access: Record<string, Permission>, cid: string): Permission | null => (accessAll ? Permission.Manage : (access[cid] ?? null));

/// A collection holding something critical.
const critical = (dir: Directory, cid: string) => dir.kidIds(`collection:${cid}`).some((x) => dir.node(x).level === Level.Critical);

/// How a member's reach of one collection reads: a reach without a second
/// factor into something critical is the worst door there is (the same rule
/// as the findings), one that changes what others use without it a warning.
function reachLevel(dir: Directory, m: Pick<Member, "twoFactor">, cid: string, perm: Permission | null): Level | null {
  if (!perm || m.twoFactor !== false) return null;
  if (critical(dir, cid)) return Level.Critical;
  return changesItems(perm) ? Level.Warning : null;
}

const PERM_WORD: Record<Permission, Key> = { [Permission.Manage]: "perm.manage", [Permission.Edit]: "perm.edit", [Permission.EditHidden]: "perm.editHidden", [Permission.Read]: "perm.read", [Permission.ReadHidden]: "perm.readHidden" };
const ROLE_WORD = (r: OrgRole): Key => `role.${r}` as Key;

// ---------- who may do what ----------

/// Why a member verb may not be used on this member, or null. These are the
/// window's own rules on top of `can`: nobody removes or demotes themself
/// here (they would lock themself out), nobody removes the last owner, and
/// only an owner touches an owner.
export function memberRefusal(dir: Directory, m: Member, op: MemberOp): Key | null {
  const org = dir.catalog.orgs.find((o) => o.id === m.orgId);
  if (!org) throw new Error(`member "${m.id}" belongs to no organisation in the catalogue`);
  return refusalOf(org, m, op, isLastOwner(dir, m));
}
export enum MemberOp {
  Role = "role",
  Remove = "remove",
  Confirm = "confirm",
}
/// The same over what a node carries. The last owner is never someone else
/// one may touch (only an owner touches an owner, and they are one too), so
/// a node's `applies` can leave it out; the preview still checks it.
function refusalOf(org: Org, m: Member, op: MemberOp, lastOwner: boolean): Key | null {
  if (!org.can.manageMembers) return "verb.org.refuse.cannotMembers";
  if (op === MemberOp.Confirm) return m.status === MemberStatus.Accepted ? null : "verb.org.refuse.notAccepted";
  if (m.status === MemberStatus.Revoked) return "verb.org.refuse.revoked";
  if (m.isYou) return op === MemberOp.Remove ? "verb.org.refuse.removeSelf" : "verb.org.refuse.roleSelf";
  if (m.role === OrgRole.Owner && org.role !== OrgRole.Owner) return "verb.org.refuse.ownerOnly";
  if (op === MemberOp.Remove && lastOwner) return "verb.org.refuse.lastOwnerRemove";
  return null;
}

const memberOn = (n: Node | null): Member | null => (n?.kind === NodeKind.Member && n.member ? n.member : null);
const isMembersPlace = (n: Node | null) => !!n && (n.kind === NodeKind.Org || (n.kind === NodeKind.Section && n.id.endsWith("/members")));
const isCollectionsPlace = (n: Node | null) => !!n && (n.kind === NodeKind.Org || (n.kind === NodeKind.Section && n.id.endsWith("/collections")));
const collectionOn = (dir: Directory, n: Node | null): Collection | null => {
  if (n?.kind !== NodeKind.Collection) return null;
  const c = dir.catalog.collections.find((x) => `collection:${x.id}` === n.id);
  if (!c) throw new Error(`collection node "${n.id}" has no collection in the catalogue`);
  return c;
};

// ---------- the argument ----------

export type AccessArg = {
  emails: string[];
  role?: OrgRole;
  accessAll?: boolean;
  /// Collection id → a level, or `null` for none.
  access: Record<string, Permission | null>;
  /// Words that are none of the above: said, and ↵ waits until they go.
  unknown: string[];
};

const SETTABLE: OrgRole[] = [OrgRole.User, OrgRole.Manager, OrgRole.Admin, OrgRole.Owner];
const PERM_IN: Record<string, Permission | null> = { manage: Permission.Manage, edit: Permission.Edit, edithidden: Permission.EditHidden, read: Permission.Read, hidden: Permission.ReadHidden, readhidden: Permission.ReadHidden, none: null };
const PERM_OUT: Record<Permission, string> = { [Permission.Manage]: "manage", [Permission.Edit]: "edit", [Permission.EditHidden]: "edithidden", [Permission.Read]: "read", [Permission.ReadHidden]: "hidden" };

/// The argument of `invite` and `role`, read.
export function parseAccess(dir: Directory, orgId: string, arg: string): AccessArg {
  const out: AccessArg = { emails: [], access: {}, unknown: [] };
  const colls = collsOf(dir, orgId);
  for (const word of arg.split(/[\s,;]+/).filter(Boolean)) {
    if (word.includes("@")) {
      out.emails.push(word);
      continue;
    }
    const m = /^([^:]+):(.+)$/.exec(word.toLowerCase());
    if (!m) {
      out.unknown.push(word);
      continue;
    }
    const [, key, val] = m as unknown as [string, string, string];
    // boundary: a typed role becomes a member only when it is one to set.
    if (key === "role" && isEnumValue(OrgRole, val) && SETTABLE.includes(val)) out.role = val;
    else if (key === "all" && (val === "yes" || val === "no")) out.accessAll = val === "yes";
    else {
      const c = colls.find((x) => collSlug(dir, x) === key);
      if (c && val in PERM_IN) out.access[c.id] = PERM_IN[val]!;
      else out.unknown.push(word);
    }
  }
  return out;
}

/// An access argument written back, in a fixed order.
export function accessArg(dir: Directory, orgId: string, a: Omit<AccessArg, "unknown"> & { unknown?: string[] }): string {
  const parts = [...a.emails];
  if (a.role) parts.push(`role:${a.role}`);
  if (a.accessAll !== undefined) parts.push(`all:${a.accessAll ? "yes" : "no"}`);
  for (const c of collsOf(dir, orgId)) {
    const p = a.access[c.id];
    if (p !== undefined) parts.push(`${collSlug(dir, c)}:${p === null ? "none" : PERM_OUT[p]}`);
  }
  return [...parts, ...(a.unknown ?? [])].join(" ");
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export type InviteList = { fresh: string[]; repeated: string[]; members: string[]; invalid: string[] };

/// The addresses typed, sorted: new ones once each, the ones said twice,
/// people already in the organisation, and what is not an address.
export function inviteList(dir: Directory, orgId: string, emails: string[]): InviteList {
  const known = new Set(membersOf(dir, orgId).map((m) => m.email.toLowerCase()));
  const out: InviteList = { fresh: [], repeated: [], members: [], invalid: [] };
  const seen = new Set<string>();
  for (const e of emails.map((x) => x.toLowerCase())) {
    if (!EMAIL.test(e)) {
      if (!out.invalid.includes(e)) out.invalid.push(e);
      continue;
    }
    if (seen.has(e)) {
      if (!out.repeated.includes(e)) out.repeated.push(e);
      continue;
    }
    seen.add(e);
    if (known.has(e)) out.members.push(e);
    else out.fresh.push(e);
  }
  return out;
}

/// A line that goes to a node and opens a verb on it: what a finding or a
/// row elsewhere runs.
export function verbLine(dir: Directory, id: string, verb: string, arg = ""): string {
  return `${dir.node(id).home.map((x) => dir.node(x).slug).join(" › ")} > ${verb}${arg ? ` ${arg}` : ""}`;
}

// ---------- the controls ----------

type Grant = { role: OrgRole; accessAll: boolean; access: Record<string, Permission> };

/// A collection's level is picked in two parts: how far (none, reads, edits,
/// manages) and, for reading and editing, whether passwords stay hidden.
type Reach = Permission.Read | Permission.Edit | Permission.Manage;
const REACHES: (Reach | null)[] = [null, Permission.Read, Permission.Edit, Permission.Manage];
const REACH_WORD: Record<string, Key> = { none: "verb.org.choice.none", read: "perm.read", edit: "perm.edit", manage: "perm.manage" };
const reachOf = (p: Permission | null): Reach | null => (p === Permission.ReadHidden ? Permission.Read : p === Permission.EditHidden ? Permission.Edit : p);
const levelOf = (r: Reach | null, hidden: boolean): Permission | null => (r === Permission.Read ? (hidden ? Permission.ReadHidden : Permission.Read) : r === Permission.Edit ? (hidden ? Permission.EditHidden : Permission.Edit) : r);
/// A level inside a sentence.
const PERM_IN_WORDS: Record<Permission, Key> = { [Permission.Manage]: "verb.org.permIn.manage", [Permission.Edit]: "verb.org.permIn.edit", [Permission.EditHidden]: "verb.org.permIn.editHidden", [Permission.Read]: "verb.org.permIn.read", [Permission.ReadHidden]: "verb.org.permIn.hidden" };

/// The role, access-all and per-collection controls over a grant; `argOf`
/// writes the argument a changed grant leads to.
function grantForm(dir: Directory, org: Org, g: Grant, argOf: (g: Grant) => string, roles: { list: OrgRole[]; off: (r: OrgRole) => Text | undefined }): FormGroup[] {
  const roleInput: Input = {
    id: "role",
    label: k("doc.role"),
    choices: roles.list.map((r): Choice => {
      const off = roles.off(r);
      return { label: k(ROLE_WORD(r)), arg: argOf({ ...g, role: r }), on: g.role === r, ...(off ? { off } : {}) };
    }),
  };
  const allInput: Input = {
    id: "all",
    label: k("verb.org.form.reach"),
    choices: [
      { label: k("verb.org.form.allColls"), arg: argOf({ ...g, accessAll: true }), on: g.accessAll },
      { label: k("verb.org.form.someColls"), arg: argOf({ ...g, accessAll: false }), on: !g.accessAll },
    ],
  };
  const perColl: Input[] = g.accessAll
    ? []
    : collsOf(dir, org.id).map(
        (c): Input => ({
          id: `coll:${c.id}`,
          label: raw(c.name),
          lead: COLL_LEAD,
          ...(() => {
            const now = g.access[c.id] ?? null;
            const hidden = hidesPasswords(now);
            const at = (p: Permission | null) => {
              const access = { ...g.access };
              if (p) access[c.id] = p;
              else delete access[c.id];
              return argOf({ ...g, access });
            };
            const r = reachOf(now);
            const canHide = r === Permission.Read || r === Permission.Edit;
            return {
              choices: REACHES.map((x): Choice => ({ label: k(REACH_WORD[x ?? "none"]!), arg: at(levelOf(x, hidden)), on: r === x })),
              toggle: { icon: "eye", label: k(hidden ? "verb.org.form.hiddenOn" : "verb.org.form.hiddenSet"), on: hidden, arg: at(levelOf(r, !hidden)), ...(canHide ? {} : { off: k("verb.org.form.hiddenOff") }) },
            };
          })(),
        }),
      );
  return [{ inputs: [roleInput] }, { title: k("doc.access"), inputs: [allInput, ...perColl] }];
}

/// A grant in words: "all collections", "Finance — passwords hidden, …",
/// "no collections".
function grantWords(dir: Directory, orgId: string, g: Grant): Text {
  if (g.accessAll) return k("verb.org.grant.all");
  const parts = collsOf(dir, orgId)
    .filter((c) => g.access[c.id])
    .map((c): Text => k("verb.org.grant.one", { coll: c.name, perm: k(PERM_IN_WORDS[g.access[c.id]!]) }));
  return parts.length ? k("verb.org.list", { list: { list: parts } }) : k("verb.org.grant.none");
}

const sideOf = (dir: Directory, m: Pick<Member, "twoFactor">, cid: string, perm: Permission | null, closed: Text): DeltaSide => {
  if (!perm) return { faint: closed };
  const lv = reachLevel(dir, m, cid, perm);
  return lv ? { level: lv, text: k(PERM_WORD[perm]) } : { faint: k(PERM_WORD[perm]) };
};
/// The side after: a reach that stays a finding keeps its mark; one that
/// stops being one says it is fine now.
const afterSide = (dir: Directory, m: Pick<Member, "twoFactor">, cid: string, before: Permission | null, perm: Permission | null, closed: Text): DeltaSide => {
  const was = reachLevel(dir, m, cid, before);
  const s = sideOf(dir, m, cid, perm, closed);
  if (was && "faint" in s && perm) return { level: Level.Healthy, text: k(PERM_WORD[perm]) };
  return s;
};

const ROLES_FOR = (org: Org): { list: OrgRole[]; ownerOff: Text | undefined } => ({
  list: SETTABLE,
  ownerOff: org.role === OrgRole.Owner ? undefined : k("verb.org.refuse.ownerOnly"),
});

// ---------- invite ----------

function invite(dir: Directory, obj: string, arg: string): Preview {
  const org = orgOf(dir.node(obj))!;
  const target = `org:${org.id}`;
  const a = parseAccess(dir, org.id, arg);
  const g: Grant = { role: a.role ?? OrgRole.User, accessAll: a.accessAll ?? false, access: Object.fromEntries(Object.entries(a.access).filter((e): e is [string, Permission] => e[1] !== null)) };
  const argOf = (emails: string[], x: Grant) =>
    accessArg(dir, org.id, {
      emails,
      ...(x.role !== OrgRole.User ? { role: x.role } : {}),
      ...(x.accessAll ? { accessAll: true } : {}),
      access: x.accessAll ? {} : x.access,
      unknown: a.unknown,
    });
  const list = inviteList(dir, org.id, a.emails);
  const roles = ROLES_FOR(org);
  const emailsInput: Input = {
    id: "emails",
    label: k("verb.org.form.emails"),
    text: a.emails.join(", "),
    placeholder: k("verb.org.form.emailsHint"),
    mono: true,
    with: (v) => argOf(v.split(/[\s,;]+/).filter(Boolean), g),
  };
  const form = grantForm(dir, org, g, (x) => argOf(a.emails, x), { list: roles.list, off: (r) => (r === OrgRole.Owner ? roles.ownerOff : undefined) });
  form[0]!.inputs.unshift(emailsInput);

  const now: Line[] = [];
  if (list.invalid.length) now.push({ level: Level.Critical, title: k("verb.org.invite.invalid", { list: { list: list.invalid } }), sub: k("verb.org.invite.invalidSub") });
  if (list.members.length) now.push({ level: Level.Unknown, title: k("verb.org.invite.already", { list: { list: list.members } }), sub: k("verb.org.invite.alreadySub") });
  if (list.repeated.length) now.push({ level: Level.Unknown, title: k("verb.org.invite.twice", { list: { list: list.repeated } }), sub: k("verb.org.invite.twiceSub") });
  if (a.unknown.length) now.push({ level: Level.Critical, title: k("verb.org.unknown", { list: { list: a.unknown } }), sub: k("verb.org.unknownSub") });
  const reached = collsOf(dir, org.id).filter((c) => effective(g.accessAll, g.access, c.id));
  const exposed = reached.filter((c) => critical(dir, c.id) && !hidesPasswords(effective(g.accessAll, g.access, c.id)));
  if (list.fresh.length && exposed.length) now.push({ level: Level.Warning, title: k("verb.org.invite.exposed", { colls: { list: exposed.map((c) => c.name) } }), sub: k("verb.org.invite.exposedSub") });

  const ms = membersOf(dir, org.id);
  const rows: Delta[] = [
    ...list.fresh.map(
      (e): Delta => ({ lead: { tile: LeadTile.Avatar, of: e, hue: Hue.Dim }, name: raw(e), mono: true, from: { faint: k("verb.org.invite.notMember") }, to: { level: Level.Unknown, text: k("verb.org.invite.becomes", { role: k(ROLE_WORD(g.role)) }) } }),
    ),
    ...(list.fresh.length
      ? reached.map((c): Delta => {
          const seers = ms.filter((m) => m.status !== MemberStatus.Revoked && effective(m.accessAll, m.access, c.id)).length;
          return { lead: COLL_LEAD, name: raw(c.name), from: { faint: k("count.members", { n: seers }) }, to: { level: Level.Unknown, text: k("verb.org.invite.gains", { n: list.fresh.length, perm: k(PERM_WORD[effective(g.accessAll, g.access, c.id)!]) }) } };
        })
      : []),
  ];
  const blocked = list.invalid.length ? k("verb.org.invite.fixInvalid") : a.unknown.length ? k("verb.org.unknownBlock") : !list.fresh.length ? k("verb.org.invite.needOne") : undefined;
  const inviteData: Invite = { emails: list.fresh, role: g.role, accessAll: g.accessAll, access: g.accessAll ? {} : g.access };
  if (g.role === OrgRole.Owner && roles.ownerOff) return { ...base(), blocked: roles.ownerOff };
  return base();

  function base(): Extract<Preview, { kind: PreviewKind.Ready }> {
    return {
      kind: PreviewKind.Ready,
      target,
      title: k("verb.org.invite.title", { org: org.name }),
      lede: k("verb.org.invite.lede"),
      form,
      steps: [
        { title: k("verb.org.invite.s1", { n: Math.max(1, list.fresh.length) }), sub: k("verb.org.invite.s1sub", { role: k(ROLE_WORD(g.role)), access: grantWords(dir, org.id, g) }) },
        { title: k("verb.invite.s2"), sub: k("verb.invite.s2sub") },
        { title: k("verb.invite.s3"), sub: k("verb.org.invite.s3sub") },
      ],
      ...(now.length ? { now } : {}),
      changes: { rows },
      stays: [{ level: Level.Healthy, title: k("verb.org.invite.stays"), sub: k("verb.org.invite.staysSub") }],
      go: list.fresh.length ? k("verb.org.invite.go", { n: list.fresh.length }) : k("verb.invite.go"),
      effect: { org: { op: OrgOp.Invite, orgId: org.id, invite: inviteData } },
      ...(blocked ? { blocked } : {}),
    };
  }
}

// ---------- a member's role and access ----------

/// The grant an argument leads to, from the member's own.
export function nextGrant(dir: Directory, m: Member, arg: string): { grant: Grant; unknown: string[]; emails: string[] } {
  const a = parseAccess(dir, m.orgId, arg);
  const access = { ...m.access };
  for (const [cid, p] of Object.entries(a.access)) {
    if (p) access[cid] = p;
    else delete access[cid];
  }
  return { grant: { role: a.role ?? m.role, accessAll: a.accessAll ?? m.accessAll, access }, unknown: a.unknown, emails: a.emails };
}

/// A grant as the difference from the member's own: what the line keeps.
function grantArg(dir: Directory, m: Member, g: Grant): string {
  const access: Record<string, Permission | null> = {};
  for (const c of collsOf(dir, m.orgId)) {
    const was = m.access[c.id] ?? null;
    const now = g.access[c.id] ?? null;
    if (was !== now) access[c.id] = now;
  }
  return accessArg(dir, m.orgId, {
    emails: [],
    ...(g.role !== m.role ? { role: g.role } : {}),
    ...(g.accessAll !== m.accessAll ? { accessAll: g.accessAll } : {}),
    access,
  });
}

function role(dir: Directory, obj: string, arg: string): Preview {
  const n = dir.node(obj);
  const m = n.member!;
  const org = orgOf(n)!;
  const { grant: g, unknown, emails } = nextGrant(dir, m, arg);
  const last = isLastOwner(dir, m);
  const roles = ROLES_FOR(org);
  const list: OrgRole[] = m.role === OrgRole.Custom ? [...roles.list, OrgRole.Custom] : roles.list;
  const form = grantForm(dir, org, g, (x) => grantArg(dir, m, x), {
    list,
    off: (r) => (r === OrgRole.Custom && m.role !== OrgRole.Custom ? k("verb.org.refuse.custom") : r === OrgRole.Owner ? roles.ownerOff : last ? k("verb.org.refuse.lastOwnerDemote") : undefined),
  });
  const closed = k("perm.closed");
  const rows: Delta[] = [];
  if (g.role !== m.role) rows.push({ lead: { tile: LeadTile.Plain, icon: "person" }, name: k("doc.role"), from: { faint: k(ROLE_WORD(m.role)) }, to: { level: Level.Healthy, text: k(ROLE_WORD(g.role)) } });
  if (g.accessAll !== m.accessAll)
    rows.push({ lead: { tile: LeadTile.Plain, icon: "people" }, name: k("doc.accessAll"), from: { faint: k(m.accessAll ? "verb.org.yes" : "verb.org.no") }, to: { level: Level.Healthy, text: k(g.accessAll ? "verb.org.yes" : "verb.org.no") } });
  const seen: string[] = [];
  let same = 0;
  for (const c of collsOf(dir, m.orgId)) {
    const before = effective(m.accessAll, m.access, c.id);
    const after = effective(g.accessAll, g.access, c.id);
    if (before === after) {
      same++;
      continue;
    }
    rows.push({ lead: COLL_LEAD, name: raw(c.name), from: sideOf(dir, m, c.id, before, closed), to: afterSide(dir, m, c.id, before, after, closed) });
    // Passwords already seen stay seen: narrowing does not take them back.
    if (before && !hidesPasswords(before) && (!after || hidesPasswords(after)) && m.status !== MemberStatus.Invited && dir.kidIds(`collection:${c.id}`).length) seen.push(c.name);
  }
  const now: Line[] = [];
  if (unknown.length || emails.length) now.push({ level: Level.Critical, title: k("verb.org.unknown", { list: { list: [...emails, ...unknown] } }), sub: k("verb.org.unknownSub") });
  if (seen.length) now.push({ level: Level.Warning, title: k("verb.org.role.seen", { colls: { list: seen } }), sub: k("verb.org.role.seenSub") });
  const blocked =
    unknown.length || emails.length
      ? k("verb.org.unknownBlock")
      : last && g.role !== OrgRole.Owner
        ? k("verb.org.refuse.lastOwnerDemote")
        : g.role === OrgRole.Owner && m.role !== OrgRole.Owner && roles.ownerOff
          ? roles.ownerOff
          : g.role === OrgRole.Custom && m.role !== OrgRole.Custom
            ? k("verb.org.refuse.custom")
            : !rows.length
              ? k("verb.org.role.nothing")
              : undefined;
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: k("verb.org.role.title", { name: nameOf(m) }),
    lede: k(m.status === MemberStatus.Invited ? "verb.org.role.ledeInvited" : "verb.org.role.lede"),
    form,
    steps: [],
    ...(now.length ? { now } : {}),
    changes: { rows },
    stays: [
      ...(same && rows.length ? [{ level: Level.Healthy, title: k("verb.org.role.staysColls", { n: same }), sub: k("verb.org.role.staysCollsSub") }] : []),
      { level: Level.Healthy, title: k("verb.org.role.staysKeys"), sub: k("verb.org.role.staysKeysSub") },
    ],
    go: k("verb.org.role.go"),
    note: k("verb.reversible"),
    effect: { org: { op: OrgOp.SetMember, orgId: m.orgId, memberId: m.id, change: { role: g.role, accessAll: g.accessAll, access: g.accessAll ? {} : g.access } } },
    ...(blocked ? { blocked } : {}),
  };
}

// ---------- confirm ----------

function confirm(dir: Directory, obj: string): Preview {
  const m = dir.node(obj).member!;
  const reach = dir.reach(m).filter((r) => r.perm);
  const risky = reach.filter((r) => reachLevel(dir, m, r.collection, r.perm) === Level.Critical);
  const coll = (cid: string) => collsOf(dir, m.orgId).find((c) => c.id === cid)!;
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: k("verb.org.confirm.title", { name: nameOf(m) }),
    lede: k("verb.org.confirm.lede", { name: nameOf(m) }),
    steps: [
      { title: k("verb.org.confirm.s1"), sub: k("verb.org.confirm.s1sub", { email: m.email }) },
      { title: k("verb.org.confirm.s2"), sub: k("verb.org.confirm.s2sub") },
      { title: k("verb.org.confirm.s3"), sub: k("verb.org.confirm.s3sub") },
    ],
    ...(risky.length
      ? { now: [{ level: Level.Critical as const, title: k("verb.org.confirm.risky", { name: nameOf(m), colls: { list: risky.map((r) => coll(r.collection).name) } }), sub: k("verb.org.confirm.riskySub") }] }
      : {}),
    changes: {
      rows: [
        { lead: nodeLead(obj), name: raw(nameOf(m)), from: { level: Level.Action, text: k("status.accepted") }, to: { level: Level.Healthy, text: k("status.confirmed") } },
        ...reach.map((r): Delta => ({ lead: COLL_LEAD, name: raw(coll(r.collection).name), from: { faint: k("verb.org.confirm.closedUntil") }, to: afterSide(dir, m, r.collection, null, r.perm, k("perm.closed")) })),
      ],
    },
    stays: [{ level: Level.Healthy, title: k("verb.org.confirm.stays"), sub: k("verb.org.confirm.staysSub") }],
    go: k("verb.org.confirm.go"),
    note: k("verb.org.confirm.note"),
    fingerprint: { orgId: m.orgId, memberId: m.id, compare: k("verb.org.confirm.compare", { name: nameOf(m) }) },
    effect: { org: { op: OrgOp.ConfirmMember, orgId: m.orgId, memberId: m.id, fingerprint: null } },
  };
}

// ---------- remove ----------

function remove(dir: Directory, obj: string): Preview {
  const m = dir.node(obj).member!;
  const org = orgOf(dir.node(obj))!;
  const reach = dir.reach(m).filter((r) => r.perm);
  const coll = (cid: string) => collsOf(dir, m.orgId).find((c) => c.id === cid)!;
  // The node's rule cannot see the last owner; the catalogue can.
  const refusal = memberRefusal(dir, m, MemberOp.Remove);
  const seenItems = m.status === MemberStatus.Invited ? 0 : reach.filter((r) => !hidesPasswords(r.perm)).reduce((s, r) => s + dir.kidIds(`collection:${r.collection}`).length, 0);
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: k("verb.org.remove.title", { name: nameOf(m), org: org.name }),
    lede: k(m.status === MemberStatus.Invited ? "verb.org.remove.ledeInvited" : "verb.org.remove.lede", { name: nameOf(m) }),
    steps: [
      { title: k("verb.org.remove.s1"), sub: k("verb.org.remove.s1sub") },
      { title: k("verb.org.remove.s2"), sub: k("verb.org.remove.s2sub") },
    ],
    ...(seenItems ? { now: [{ level: Level.Warning as const, title: k("verb.org.remove.seen", { items: k("count.items", { n: seenItems }) }), sub: k("verb.org.remove.seenSub") }] } : {}),
    changes: {
      rows: [
        { lead: nodeLead(obj), name: raw(nameOf(m)), from: { faint: k(`status.${m.status}` as Key) }, to: { faint: k("verb.org.remove.gone") } },
        ...reach.map((r): Delta => ({ lead: COLL_LEAD, name: raw(coll(r.collection).name), from: sideOf(dir, m, r.collection, r.perm, k("perm.closed")), to: { faint: k("perm.none") } })),
      ],
    },
    stays: [
      { level: Level.Healthy, title: k("verb.org.remove.staysItems"), sub: k("verb.org.remove.staysItemsSub") },
      { level: Level.Healthy, title: k("verb.org.remove.staysOwn"), sub: k("verb.org.remove.staysOwnSub") },
    ],
    go: k("verb.org.remove.go"),
    danger: true,
    effect: { org: { op: OrgOp.RemoveMember, orgId: m.orgId, memberId: m.id } },
    ...(refusal ? { blocked: k(refusal, { name: nameOf(m), org: org.name }) } : {}),
  };
}

// ---------- collections ----------

const nameTaken = (dir: Directory, orgId: string, name: string, except?: string) =>
  collsOf(dir, orgId).some((c) => c.id !== except && c.name.trim().toLowerCase() === name.trim().toLowerCase());

function newCollection(dir: Directory, obj: string, arg: string): Preview {
  const org = orgOf(dir.node(obj))!;
  const name = arg.trim();
  const all = membersOf(dir, org.id).filter((m) => m.accessAll && m.status !== MemberStatus.Revoked);
  const blocked = !name ? k("verb.org.coll.needName") : nameTaken(dir, org.id, name) ? k("verb.org.coll.taken", { org: org.name, name }) : undefined;
  return {
    kind: PreviewKind.Ready,
    target: `org:${org.id}`,
    title: name ? k("verb.org.newColl.titleNamed", { name }) : k("verb.org.newColl.title"),
    lede: k("verb.org.newColl.lede", { org: org.name }),
    form: [{ inputs: [{ id: "name", label: k("verb.org.form.name"), text: arg, placeholder: k("verb.org.form.nameHint"), with: (v) => v }] }],
    steps: [
      { title: k("verb.org.newColl.s1"), sub: k("verb.org.newColl.s1sub") },
      { title: k("verb.org.newColl.s2"), sub: k("verb.org.newColl.s2sub") },
    ],
    changes: {
      rows: [
        { lead: COLL_LEAD, name: name ? raw(name) : k("verb.org.coll.unnamed"), from: { faint: k("verb.org.newColl.none") }, to: { level: Level.Healthy, text: k("verb.org.newColl.empty") } },
        // Who reaches every collection reaches this one at once.
        ...all.map((m): Delta => ({ lead: nodeLead(`member:${m.id}`), name: raw(nameOf(m)), from: { faint: k("verb.org.newColl.none") }, to: { faint: k("verb.org.newColl.viaAll") } })),
      ],
    },
    stays: [{ level: Level.Healthy, title: k("verb.org.newColl.others"), sub: k("verb.org.newColl.othersSub") }],
    go: k("verb.org.newColl.go"),
    effect: { org: { op: OrgOp.CreateCollection, orgId: org.id, name } },
    ...(blocked ? { blocked } : {}),
  };
}

function rename(dir: Directory, obj: string, arg: string): Preview {
  const c = collectionOn(dir, dir.node(obj))!;
  const org = orgOf(dir.node(obj))!;
  const name = arg.trim();
  const blocked = !name
    ? k("verb.org.rename.typeName")
    : name === c.name
      ? k("verb.org.rename.same")
      : nameTaken(dir, c.orgId, name, c.id)
        ? k("verb.org.coll.taken", { org: org.name, name })
        : undefined;
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: k("verb.org.rename.title", { name: c.name }),
    lede: k("verb.org.rename.lede"),
    form: [{ inputs: [{ id: "name", label: k("verb.org.form.name"), text: arg || c.name, placeholder: raw(c.name), with: (v) => v }] }],
    steps: [],
    changes: { rows: [{ lead: COLL_LEAD, name: k("verb.org.form.name"), from: { faint: raw(c.name) }, to: name && name !== c.name ? { level: Level.Healthy, text: raw(name) } : { faint: k("verb.unchanged") } }] },
    stays: [{ level: Level.Healthy, title: k("verb.org.rename.stays"), sub: k("verb.org.rename.staysSub") }],
    go: k("verb.org.rename.go"),
    note: k("verb.reversible"),
    effect: { org: { op: OrgOp.RenameCollection, orgId: c.orgId, id: c.id, name } },
    ...(blocked ? { blocked } : {}),
  };
}

function del(dir: Directory, obj: string): Preview {
  const c = collectionOn(dir, dir.node(obj))!;
  const items = dir.kidIds(obj).map((x) => dir.node(x));
  const orphans = items.filter((x) => x.item!.collectionIds.length === 1);
  const who = membersOf(dir, c.orgId).filter((m) => !m.accessAll && m.access[c.id] && m.status !== MemberStatus.Revoked);
  const other = (x: Node) => {
    const cid = x.item!.collectionIds.find((y) => y !== c.id)!;
    return dir.node(`collection:${cid}`).name;
  };
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: k("verb.org.delete.title", { name: c.name }),
    lede: k("verb.org.delete.lede"),
    steps: [
      { title: k("verb.org.delete.s1"), sub: k("verb.org.delete.s1sub") },
      { title: k("verb.org.delete.s2"), sub: k("verb.org.delete.s2sub") },
    ],
    ...(orphans.length ? { now: [{ level: Level.Warning as const, title: k("verb.org.delete.orphans", { items: k("count.items", { n: orphans.length }) }), sub: k("verb.org.delete.orphansSub") }] } : {}),
    changes: {
      rows: [
        ...items.map(
          (x): Delta => ({
            lead: nodeLead(x.id),
            name: x.name,
            from: { faint: k("verb.org.delete.inColl", { coll: c.name }) },
            to: x.item!.collectionIds.length === 1 ? { level: Level.Warning, text: k("verb.org.delete.noColl") } : { faint: k("verb.org.delete.stillIn", { coll: other(x) }) },
          }),
        ),
        ...who.map((m): Delta => ({ lead: nodeLead(`member:${m.id}`), name: raw(nameOf(m)), from: { faint: k(PERM_WORD[m.access[c.id]!]) }, to: { faint: k("perm.none") } })),
      ],
      count: items.length + who.length,
    },
    stays: [{ level: Level.Healthy, title: k("verb.org.delete.stays"), sub: k("verb.org.delete.staysSub") }],
    go: k("verb.org.delete.go"),
    danger: true,
    effect: { org: { op: OrgOp.DeleteCollection, orgId: c.orgId, id: c.id } },
  };
}

// ---------- refusals ----------

/// A preview that cannot run, saying why: the verb is known and fits the
/// object, but here it would lock someone out or the server does not allow it.
function refused(target: string, title: Text, why: Text, go: Text): Preview {
  return { kind: PreviewKind.Ready, target, title, lede: why, steps: [], go, blocked: k("verb.org.refuse.short"), effect: { none: true } };
}

function memberRefuses(op: MemberOp, title: (m: Member, dir: Directory) => Text, go: Key) {
  return (dir: Directory, obj: string): Preview | null => {
    const m = memberOn(dir.node(obj));
    if (!m) return null;
    const why = memberRefusal(dir, m, op);
    return why ? refused(obj, title(m, dir), k(why, { name: nameOf(m), org: dir.node(`org:${m.orgId}`).name }), k(go)) : null;
  };
}

function orgRefuses(place: (n: Node) => boolean, ability: "manageMembers" | "manageCollections", title: Key, go: Key) {
  return (dir: Directory, obj: string): Preview | null => {
    const n = dir.node(obj);
    const org = orgOf(n);
    if (!org || !place(n) || org.can[ability]) return null;
    const why = k(ability === "manageMembers" ? "verb.org.refuse.cannotMembers" : "verb.org.refuse.cannotCollections", { org: org.name });
    return refused(n.id, k(title), why, k(go));
  };
}

// ---------- the verbs ----------

const canMembers = (n: Node | null) => !!orgOf(n)?.can.manageMembers;
const canCollections = (n: Node | null) => !!orgOf(n)?.can.manageCollections;
/// A node offers a member verb only where it would run.
const memberFits = (op: MemberOp) => (n: Node | null) => {
  const m = memberOn(n);
  const org = orgOf(n);
  return !!m && !!org && refusalOf(org, m, op, false) === null;
};

/// The members' email as the crumb says the invite: the addresses, or the
/// changes of a role, in words.
function inviteName(dir: Directory, obj: string | null, arg: string): Text | null {
  const org = orgOf(obj ? dir.node(obj) : null);
  if (!org) return null;
  const a = parseAccess(dir, org.id, arg);
  return a.emails.length ? k("verb.org.list", { list: { list: a.emails } }) : null;
}
function roleName(dir: Directory, obj: string | null, arg: string): Text | null {
  const m = memberOn(obj ? dir.node(obj) : null);
  if (!m) return null;
  const { grant: g } = nextGrant(dir, m, arg);
  const parts: Text[] = [];
  if (g.role !== m.role) parts.push(k(ROLE_WORD(g.role)));
  if (g.accessAll !== m.accessAll) parts.push(k(g.accessAll ? "verb.org.grant.all" : "verb.org.form.someColls"));
  for (const c of collsOf(dir, m.orgId)) {
    const was = effective(m.accessAll, m.access, c.id);
    const now = effective(g.accessAll, g.access, c.id);
    if (was !== now && !g.accessAll) parts.push(k("verb.org.grant.one", { coll: c.name, perm: k(now ? PERM_IN_WORDS[now] : "verb.org.permIn.none") }));
  }
  return parts.length ? k("verb.org.list", { list: { list: parts } }) : null;
}

const firstOrgWith = (ability: "manageMembers" | "manageCollections") => (dir: Directory) => {
  const o = dir.catalog.orgs.find((x) => x.can[ability] && dir.has(`org:${x.id}`));
  return o ? `org:${o.id}` : null;
};
const firstMember = (op: MemberOp) => (dir: Directory) => {
  const m = dir.catalog.members.find((x) => dir.has(`member:${x.id}`) && memberRefusal(dir, x, op) === null);
  return m ? `member:${m.id}` : null;
};
const firstCollection = (dir: Directory) => {
  const c = dir.catalog.collections.find((x) => dir.catalog.orgs.find((o) => o.id === x.orgId)?.can.manageCollections && dir.has(`collection:${x.id}`));
  return c ? `collection:${c.id}` : null;
};

export const ORG_VERBS: Verb[] = [
  { id: "invite", name: k("verb.invite"), icon: "mail", applies: (n) => isMembersPlace(n) && canMembers(n), refuses: orgRefuses(isMembersPlace, "manageMembers", "verb.invite", "verb.invite.go"), preview: invite, example: firstOrgWith("manageMembers"), argName: inviteName },
  {
    id: "role",
    name: k("verb.org.role"),
    icon: "people",
    applies: memberFits(MemberOp.Role),
    refuses: memberRefuses(MemberOp.Role, (m) => k("verb.org.role.title", { name: nameOf(m) }), "verb.org.role.go"),
    preview: role,
    example: firstMember(MemberOp.Role),
    argName: roleName,
  },
  { id: "confirm", name: k("verb.org.confirm"), icon: "check", applies: memberFits(MemberOp.Confirm), refuses: memberRefuses(MemberOp.Confirm, (m) => k("verb.org.confirm.title", { name: nameOf(m) }), "verb.org.confirm.go"), preview: confirm, example: firstMember(MemberOp.Confirm) },
  { id: "remove", name: k("verb.org.remove"), icon: "trash", applies: memberFits(MemberOp.Remove), refuses: memberRefuses(MemberOp.Remove, (m, dir) => k("verb.org.remove.title", { name: nameOf(m), org: dir.node(`org:${m.orgId}`).name }), "verb.org.remove.go"), preview: remove, example: firstMember(MemberOp.Remove) },
  {
    id: "new collection",
    name: k("doc.newCollection"),
    icon: "stack",
    applies: (n) => isCollectionsPlace(n) && canCollections(n),
    refuses: orgRefuses(isCollectionsPlace, "manageCollections", "doc.newCollection", "verb.org.newColl.go"),
    preview: newCollection,
    example: firstOrgWith("manageCollections"),
    argName: (_d, _o, arg) => (arg.trim() ? raw(arg.trim()) : null),
  },
  { id: "rename", name: k("verb.org.rename"), icon: "edit", applies: (n) => n?.kind === NodeKind.Collection && canCollections(n), refuses: orgRefuses((n) => n.kind === NodeKind.Collection, "manageCollections", "verb.org.rename", "verb.org.rename.go"), preview: rename, example: firstCollection, argName: (_d, _o, arg) => (arg.trim() ? raw(arg.trim()) : null) },
  { id: "delete", name: k("verb.org.delete"), icon: "trash", applies: (n) => n?.kind === NodeKind.Collection && canCollections(n), refuses: orgRefuses((n) => n.kind === NodeKind.Collection, "manageCollections", "verb.org.delete", "verb.org.delete.go"), preview: del, example: firstCollection },
];

/// A confirm with the words the window has on screen for that member;
/// any other change as it is. Without shown words the confirm stays without
/// them, and `runOrgWrite` refuses it.
export function withShownFingerprint(e: OrgWrite, shown: (orgId: string, memberId: string) => string[] | null): OrgWrite {
  if (e.op !== OrgOp.ConfirmMember) return e;
  const words = shown(e.orgId, e.memberId);
  return words ? { ...e, fingerprint: [...words] } : e;
}

/// Runs an organisation's change through the app's writes; a new
/// collection's id for a new one.
export async function runOrgWrite(w: Writes, e: OrgWrite): Promise<string | null> {
  switch (e.op) {
    case OrgOp.Invite:
      await w.invite(e.orgId, e.invite);
      return null;
    case OrgOp.SetMember:
      await w.setMember(e.orgId, e.memberId, e.change);
      return null;
    case OrgOp.ConfirmMember:
      // Words nobody was shown are no check at all: refused before the call.
      if (!e.fingerprint) throw new Error("err.fingerprintNotShown");
      await w.confirmMember(e.orgId, e.memberId, e.fingerprint);
      return null;
    case OrgOp.RemoveMember:
      await w.removeMember(e.orgId, e.memberId);
      return null;
    case OrgOp.CreateCollection:
      return w.createCollection(e.orgId, e.name);
    case OrgOp.RenameCollection:
      await w.renameCollection(e.orgId, e.id, e.name);
      return null;
    case OrgOp.DeleteCollection:
      await w.deleteCollection(e.orgId, e.id);
      return null;
  }
}

/// Where the window stands once a change is made: on what it changed, or,
/// when that is gone, on the place that held it.
export function orgLanding(e: OrgWrite, newId: string | null): string {
  switch (e.op) {
    case OrgOp.Invite:
    case OrgOp.RemoveMember:
      return `org:${e.orgId}/members`;
    case OrgOp.SetMember:
    case OrgOp.ConfirmMember:
      return `member:${e.memberId}`;
    case OrgOp.CreateCollection:
      if (!newId) throw new Error("a new collection came back without an id");
      return `collection:${newId}`;
    case OrgOp.RenameCollection:
      return `collection:${e.id}`;
    case OrgOp.DeleteCollection:
      return `org:${e.orgId}/collections`;
  }
}
