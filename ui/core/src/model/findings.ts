// What needs doing in an organisation, read off its members, collections,
// items and policies: the document's "First this" and the access map's
// findings are the same list, so the two never disagree. Pure.
import type { Key, Text } from "../i18n";
import type { Directory } from "../path/directory";
import { policyLevel } from "../path/directory";
import { changesItems, hidesPasswords, Level, type Member, Permission, MemberStatus, PolicyType } from "./types";
import { accessArg, ORG_VERBS, verbLine } from "../verbs/org";

export type OrgFinding = {
  level: Level;
  title: Text;
  sub: Text;
  /// The node the finding is about: the map lights it, the document opens it.
  focus: string;
  /// Where it is said: on the document, on the map, or both.
  doc: boolean;
  map: boolean;
  /// The document's action for it.
  action: { label: Key; act: { verb: string } | { map: true } | { go: string } | { run: string } };
};

const VERB: Record<Permission, Key> = { [Permission.Manage]: "find.manages", [Permission.Edit]: "find.edits", [Permission.EditHidden]: "find.edits", [Permission.Read]: "find.reads", [Permission.ReadHidden]: "find.reads" };

export function orgFindings(dir: Directory, orgId: string): OrgFinding[] {
  const oid = orgId.startsWith("org:") ? orgId.slice(4) : orgId;
  const { members, collections, items } = dir.catalog;
  const ms = members.filter((m) => m.orgId === oid);
  const cs = collections.filter((c) => c.orgId === oid);
  const live = items.filter((i) => !i.deleted && i.orgId === oid);
  // Asked per member and collection, and per critical item: worked out once
  // per collection.
  const crits = new Map<string, boolean>();
  const crit = (cid: string) => {
    let c = crits.get(cid);
    if (c === undefined) crits.set(cid, (c = live.some((i) => i.collectionIds.includes(cid) && dir.node(`item:${i.id}`).level === Level.Critical)));
    return c;
  };
  const org = dir.catalog.orgs.find((o) => o.id === oid);
  const membersKnown = !dir.catalog.membersLoading && (org?.can.manageMembers ?? false);
  const name = (m: Member) => m.name ?? m.email;
  const seen = new Map<string, number>();
  const seeing = (cid: string) => {
    let n = seen.get(cid);
    if (n === undefined) seen.set(cid, (n = ms.filter((m) => m.status !== MemberStatus.Invited && (m.accessAll || m.access[cid])).length));
    return n;
  };
  const out: OrgFinding[] = [];

  // A member without a second factor who reaches a collection holding
  // something critical: the worst door there is.
  const loudMembers = new Set<string>();
  for (const m of ms.filter((x) => x.twoFactor === false && x.status !== MemberStatus.Invited)) {
    for (const r of dir.reach(m)) {
      if (!r.perm || !crit(r.collection)) continue;
      const c = cs.find((x) => x.id === r.collection)!;
      loudMembers.add(m.id);
      // Where the one looking may narrow it, the finding opens that, with
      // the collection already set one step down: passwords hidden, or,
      // where they already are, closed.
      const node = dir.node(`member:${m.id}`);
      const role = ORG_VERBS.find((v) => v.id === "role")!;
      const narrow = role.applies(node) ? verbLine(dir, node.id, "role", accessArg(dir, oid, { emails: [], access: { [c.id]: r.perm === Permission.ReadHidden ? null : Permission.ReadHidden } })) : null;
      out.push({
        level: Level.Critical,
        title: { key: "find.noTwoFactorReach", args: { name: name(m), verb: { key: VERB[r.perm] }, coll: c.name } },
        sub: { key: hidesPasswords(r.perm) ? "find.hiddenButSeen" : "find.seesPasswords" },
        focus: `member:${m.id}`,
        doc: true,
        map: true,
        action: narrow ? { label: "find.narrow", act: { run: narrow } } : { label: "find.showOnMap", act: { map: true } },
      });
    }
  }
  // A critical item everyone in its collection sees.
  for (const i of live) {
    const n = dir.node(`item:${i.id}`);
    if (n.level !== Level.Critical) continue;
    const c = cs.find((x) => i.collectionIds.includes(x.id));
    if (!c) continue;
    out.push({
      level: Level.Critical,
      title: { key: "find.itemCritical", args: { name: i.name, why: n.why ?? { key: "level.critical" } } },
      // Who sees it is said only where it is known: members still loading,
      // or not visible to this role, would read as "seen by none".
      sub: membersKnown
        ? { key: "find.itemSeen", args: { coll: c.name, members: { key: "count.members", args: { n: seeing(c.id) } } } }
        : { key: "find.itemIn", args: { coll: c.name } },
      focus: n.id,
      doc: true,
      map: true,
      action: { label: "find.open", act: { go: n.id } },
    });
  }
  // A second factor the organisation does not ask for, while some sign in
  // without one.
  const without = ms.filter((m) => m.twoFactor === false);
  const tf = dir.catalog.policies?.find((p) => p.orgId === oid && p.type === PolicyType.TwoFactor);
  if (tf && policyLevel(tf) !== Level.Healthy && without.length)
    out.push({
      level: Level.Action,
      title: { key: "find.twoFactorOptional" },
      sub: { key: "find.signInWithout", args: { names: { list: without.map(name) } } },
      focus: `org:${oid}/policies`,
      doc: true,
      map: false,
      action: { label: "find.require", act: { verb: "require 2fa" } },
    });
  // A member without a second factor who changes what others use.
  for (const m of without.filter((x) => !loudMembers.has(x.id) && x.status !== MemberStatus.Invited)) {
    const ed = dir.reach(m).filter((r) => changesItems(r.perm));
    if (!ed.length) continue;
    out.push({
      level: Level.Warning,
      title: { key: "find.noTwoFactorEdits", args: { name: name(m), colls: { list: ed.map((r) => cs.find((c) => c.id === r.collection)!.name) } } },
      sub: { key: "find.seesPasswords" },
      focus: `member:${m.id}`,
      doc: false,
      map: true,
      action: { label: "find.open", act: { go: `member:${m.id}` } },
    });
  }
  const invited = ms.filter((m) => m.status === MemberStatus.Invited);
  if (invited.length)
    out.push({
      level: Level.Unknown,
      title: { key: "find.invites", args: { n: invited.length } },
      sub: { key: "find.invitesSub" },
      focus: `member:${invited[0]!.id}`,
      doc: false,
      map: true,
      action: { label: "find.open", act: { go: `member:${invited[0]!.id}` } },
    });
  return out;
}
