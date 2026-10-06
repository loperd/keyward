// Running an organisation: which verbs are offered where, the rules that keep
// the one looking from locking themself (or everyone) out, what each preview
// says before ↵, and how an invite's addresses are read.
import { beforeEach, describe, expect, it } from "vitest";
import { DEMO, DEMO_NOW } from "../demo";
import { DemoBackend } from "../demo-backend";
import { DEMO_FINGERPRINT, DemoWrites } from "../demo-writes";
import { buildDoc } from "../doc/build";
import { setLang, text, LANGS, type Text, Lang } from "../i18n";
import { orgFindings } from "../model/findings";
import { type Catalog, OrgRole } from "../model/types";
import { Directory } from "../path/directory";
import { Query } from "../path/query";
import { CORE_VERBS, previewOf } from "./core";
import { accessArg, inviteList, isLastOwner, memberRefusal, ORG_VERBS, parseAccess, runOrgWrite, verbLine, withShownFingerprint, MemberOp } from "./org";
import { type Delta, type Preview, PreviewKind, OrgOp } from "./spec";
import { LeadTile } from "../doc/spec";

const dirOf = (c: Catalog = DEMO) => new Directory(c, [], { now: DEMO_NOW });
const ready = (p: Preview) => {
  if (p.kind !== PreviewKind.Ready) throw new Error(`expected a ready preview, got ${p.kind}`);
  return p;
};
const say = (x: Text) => text(x);
const preview = (d: Directory, verb: string, obj: string, arg = "") => ready(previewOf(d, CORE_VERBS, verb, obj, arg));
const applies = (d: Directory, verb: string, id: string) => ORG_VERBS.find((v) => v.id === verb)!.applies(d.node(id));
const row = (p: Extract<Preview, { kind: PreviewKind.Ready }>, name: string): Delta => {
  const r = p.changes?.rows.find((x) => say(x.name) === name);
  if (!r) throw new Error(`no row "${name}" in ${p.changes?.rows.map((x) => say(x.name)).join(", ")}`);
  return r;
};
const side = (s: Delta["from"]) => ("faint" in s ? { faint: say(s.faint) } : { level: s.level, text: say(s.text) });

/// The demo with Acme seen by an admin instead of its owner.
function asAdmin(): Catalog {
  const c = structuredClone(DEMO);
  c.orgs.find((o) => o.id === "acme")!.role = OrgRole.Admin;
  c.members.find((m) => m.id === "alex")!.role = OrgRole.Admin;
  c.members.find((m) => m.id === "priya")!.role = OrgRole.Owner;
  return c;
}

beforeEach(() => setLang(Lang.En));

describe("organisation verbs are offered", () => {
  it("only where the organisation's abilities allow them", () => {
    const d = dirOf();
    for (const id of ["org:acme", "org:acme/members"]) expect(applies(d, "invite", id)).toBe(true);
    for (const id of ["org:acme", "org:acme/collections"]) expect(applies(d, "new collection", id)).toBe(true);
    expect(applies(d, "rename", "collection:finance")).toBe(true);
    expect(applies(d, "delete", "collection:finance")).toBe(true);
    expect(applies(d, "role", "member:tomas")).toBe(true);
    expect(applies(d, "confirm", "member:tomas")).toBe(true);
    expect(applies(d, "confirm", "member:dana")).toBe(false);
    // Globex: the one looking is a user there.
    for (const v of ["invite", "new collection"]) expect(applies(d, v, "org:globex")).toBe(false);
    expect(applies(d, "rename", "collection:ops")).toBe(false);
    expect(applies(d, "delete", "collection:ops")).toBe(false);
  });
  it("and typed where they are not, explain why instead of running", () => {
    const d = dirOf();
    const p = preview(d, "invite", "org:globex");
    expect(p.blocked).toBeDefined();
    expect(say(p.lede)).toContain("Globex");
    expect("none" in p.effect).toBe(true);
    expect(preview(d, "delete", "collection:ops").blocked).toBeDefined();
  });
  it("on the pages: no role or removal on yourself, a confirm while someone waits", () => {
    const d = dirOf();
    const doc = (id: string) => buildDoc({ dir: d, detail: null, server: "s", places: [] }, id);
    const acts = (id: string) => {
      const h = doc(id).hero;
      const mine = new Set(ORG_VERBS.map((v) => v.id));
      return [h.primary, ...(h.more ?? [])].flatMap((a) => (a && "verb" in a.act && mine.has(a.act.verb) ? [a.act.verb] : []));
    };
    expect(acts("member:alex")).not.toContain("role");
    expect(acts("member:alex")).not.toContain("remove");
    expect(acts("member:tomas").slice(0, 1)).toEqual(["confirm"]);
    expect(acts("member:tomas")).toEqual(expect.arrayContaining(["role", "remove"]));
    expect(acts("collection:finance")).toEqual(expect.arrayContaining(["rename", "delete"]));
    expect(acts("collection:ops")).toEqual([]);
    expect(acts("org:acme")).toEqual(expect.arrayContaining(["invite", "new collection"]));
    expect(acts("org:globex")).toEqual([]);
  });
});

describe("the rules that keep someone in charge", () => {
  it("never remove or demote yourself", () => {
    const d = dirOf();
    const alex = d.catalog.members.find((m) => m.id === "alex")!;
    expect(memberRefusal(d, alex, MemberOp.Remove)).toBe("verb.org.refuse.removeSelf");
    expect(memberRefusal(d, alex, MemberOp.Role)).toBe("verb.org.refuse.roleSelf");
    expect(applies(d, "remove", "member:alex")).toBe(false);
    const p = preview(d, "remove", "member:alex");
    expect(p.blocked).toBeDefined();
    expect("none" in p.effect).toBe(true);
    expect(preview(d, "role", "member:alex").blocked).toBeDefined();
  });
  it("let only an owner touch an owner, or make one", () => {
    const d = dirOf(asAdmin());
    expect(applies(d, "role", "member:priya")).toBe(false);
    expect(applies(d, "remove", "member:priya")).toBe(false);
    expect(say(preview(d, "remove", "member:priya").lede)).toMatch(/owner/i);
    const p = preview(d, "role", "member:dana");
    const owner = p.form!.flatMap((g) => g.inputs).find((i) => i.id === "role")!;
    expect("choices" in owner && owner.choices.find((c) => say(c.label) === "Owner")!.off).toBeDefined();
    expect(preview(d, "role", "member:dana", "role:owner").blocked).toBeDefined();
    expect(preview(d, "invite", "org:acme", "new@acme.example role:owner").blocked).toBeDefined();
  });
  it("keep the last owner an owner, and in the organisation", () => {
    // An owner whose own row is not shown, and one other owner: that one is
    // the last confirmed owner.
    const c = structuredClone(DEMO);
    c.members = c.members.filter((m) => m.id !== "alex");
    c.members.find((m) => m.id === "priya")!.role = OrgRole.Owner;
    const d = dirOf(c);
    const priya = d.catalog.members.find((m) => m.id === "priya")!;
    expect(isLastOwner(d, priya)).toBe(true);
    const demote = preview(d, "role", "member:priya", "role:user");
    expect(say(demote.blocked!)).toMatch(/only owner/i);
    const remove = preview(d, "remove", "member:priya");
    expect(remove.blocked).toBeDefined();
    const roles = demote.form!.flatMap((g) => g.inputs).find((i) => i.id === "role")!;
    expect("choices" in roles && roles.choices.filter((x) => x.off).map((x) => say(x.label))).toEqual(["User", "Manager", "Admin"]);
  });
});

describe("previews say before and after", () => {
  it("a role change narrows Tomás's Finance from a critical reach to closed", () => {
    const d = dirOf();
    const p = preview(d, "role", "member:tomas", "finance:none");
    const r = row(p, "Finance");
    expect(side(r.from)).toEqual({ level: "critical", text: "Without passwords" });
    expect(side(r.to)).toEqual({ faint: "Closed" });
    expect(p.blocked).toBeUndefined();
    expect(p.effect).toEqual({ org: { op: "setMember", orgId: "acme", memberId: "tomas", change: { role: "user", accessAll: false, access: { shared: "read" } } } });
  });
  it("a role change says the new role, and nothing to do when nothing changes", () => {
    const d = dirOf();
    const p = preview(d, "role", "member:sam", "role:manager platform:edit");
    expect(side(row(p, "Role").from)).toEqual({ faint: "User" });
    expect(side(row(p, "Role").to)).toEqual({ level: "healthy", text: "Manager" });
    expect(side(row(p, "Platform").from)).toEqual({ faint: "Reads" });
    expect(side(row(p, "Platform").to)).toEqual({ faint: "Edits" });
    expect(say(preview(d, "role", "member:sam").blocked!)).toBe("Pick what to change");
    expect(preview(d, "role", "member:sam", "finance:fly").blocked).toBeDefined();
  });
  it("a role's controls write the argument as the difference from now", () => {
    const d = dirOf();
    const fin = (arg: string) => {
      const i = preview(d, "role", "member:tomas", arg).form!.flatMap((g) => g.inputs).find((x) => x.id === "coll:finance")!;
      if (!("choices" in i)) throw new Error("Finance is a choice");
      return i;
    };
    // Tomás reads Finance with passwords hidden: "Reads", the switch on.
    const now = fin("");
    expect(say(now.choices.find((c) => c.on)!.label)).toBe("Reads");
    expect(now.toggle!.on).toBe(true);
    expect(now.toggle!.arg).toBe("finance:read");
    expect(now.choices.find((c) => say(c.label) === "Edits")!.arg).toBe("finance:edithidden");
    expect(now.choices.find((c) => say(c.label) === "None")!.arg).toBe("finance:none");
    // Closed: nothing to hide.
    const closed = fin("finance:none");
    expect(closed.choices.find((c) => c.on)!.arg).toBe("finance:none");
    expect(closed.toggle!.off).toBeDefined();
    const all = preview(d, "role", "member:tomas", "finance:none").form!.flatMap((g) => g.inputs).find((i) => i.id === "all")!;
    if (!("choices" in all)) throw new Error("access-all is a choice");
    expect(all.choices[0]!.arg).toBe("all:yes finance:none");
  });
  it("keep editing without passwords as its own level", () => {
    const d = dirOf();
    const p = preview(d, "role", "member:tomas", "finance:edithidden");
    expect(side(row(p, "Finance").to)).toEqual({ level: "critical", text: "Edits, without passwords" });
    expect(p.effect).toMatchObject({ org: { change: { access: { finance: "editHidden", shared: "read" } } } });
    expect(parseAccess(d, "acme", "finance:edithidden").access).toEqual({ finance: "editHidden" });
  });
  it("confirming opens what was given, and says the key is sealed for them", () => {
    const d = dirOf();
    const p = preview(d, "confirm", "member:tomas");
    expect(side(row(p, "Tomás Ortega").from)).toEqual({ level: "action", text: "Awaiting confirmation" });
    expect(side(row(p, "Tomás Ortega").to)).toEqual({ level: "healthy", text: "Confirmed" });
    expect(side(row(p, "Finance").to).text ?? "").toBe("Without passwords");
    expect(say(p.lede)).toMatch(/public key/);
    expect(p.now?.[0]?.level).toBe("critical");
    // The words are not known to the preview: the window fills in what it showed.
    expect(p.effect).toEqual({ org: { op: OrgOp.ConfirmMember, orgId: "acme", memberId: "tomas", fingerprint: null } });
    expect(p.fingerprint).toMatchObject({ orgId: "acme", memberId: "tomas" });
    expect(say(p.fingerprint!.compare)).toMatch(/Tomás Ortega/);
    expect(preview(d, "confirm", "member:dana").blocked).toBeDefined();
  });
  it("removing a member is a danger that lists what they lose", () => {
    const d = dirOf();
    const p = preview(d, "remove", "member:marco");
    expect(p.danger).toBe(true);
    expect(side(row(p, "Platform").to)).toEqual({ faint: "No access" });
    expect(side(row(p, "Shared").to)).toEqual({ faint: "No access" });
    expect(p.now?.[0]?.level).toBe("warning");
    expect(p.effect).toEqual({ org: { op: OrgOp.RemoveMember, orgId: "acme", memberId: "marco" } });
  });
  it("deleting a collection lists the items that lose it", () => {
    const d = dirOf();
    const p = preview(d, "delete", "collection:finance");
    const items = d.kidIds("collection:finance");
    expect(items.length).toBeGreaterThan(0);
    for (const id of items) expect(p.changes!.rows.some((r) => r.lead.tile === LeadTile.Node && r.lead.id === id)).toBe(true);
    expect(p.danger).toBe(true);
    expect(p.effect).toEqual({ org: { op: "deleteCollection", orgId: "acme", id: "finance" } });
  });
  it("a new collection needs a name of its own; a rename a new one", () => {
    const d = dirOf();
    expect(preview(d, "new collection", "org:acme").blocked).toBeDefined();
    expect(say(preview(d, "new collection", "org:acme", "finance").blocked!)).toContain("Acme");
    expect(preview(d, "new collection", "org:acme", "Big Money").effect).toEqual({ org: { op: "createCollection", orgId: "acme", name: "Big Money" } });
    expect(preview(d, "rename", "collection:finance", "Finance").blocked).toBeDefined();
    expect(preview(d, "rename", "collection:finance", "Shared").blocked).toBeDefined();
    expect(preview(d, "rename", "collection:finance", "Money").effect).toEqual({ org: { op: "renameCollection", orgId: "acme", id: "finance", name: "Money" } });
  });
  it("read in both languages, whatever the argument", () => {
    const d = dirOf();
    const cases: [string, string, string][] = [
      ["invite", "org:acme", "a@x.example lena@acme.example a@x.example nope role:manager finance:hidden"],
      ["invite", "org:acme", "all:yes x@y.example"],
      ["role", "member:tomas", "finance:none role:admin"],
      ["role", "member:alex", ""],
      ["confirm", "member:tomas", ""],
      ["remove", "member:marco", ""],
      ["remove", "member:alex", ""],
      ["new collection", "org:acme", "Big Money"],
      ["rename", "collection:finance", "Money"],
      ["delete", "collection:finance", ""],
      ["invite", "org:globex", ""],
    ];
    const texts = (v: unknown, out: Text[] = []): Text[] => {
      if (Array.isArray(v)) v.forEach((x) => texts(x, out));
      else if (v && typeof v === "object") {
        const o = v as Record<string, unknown>;
        if (("key" in o && typeof o.key === "string") || ("raw" in o && Object.keys(o).length === 1)) out.push(o as Text);
        else Object.values(o).forEach((x) => texts(x, out));
      }
      return out;
    };
    for (const l of LANGS) {
      setLang(l);
      for (const [v, o, a] of cases) for (const x of texts(previewOf(d, CORE_VERBS, v, o, a))) expect(() => text(x)).not.toThrow();
    }
  });
});

describe("an invite's addresses", () => {
  it("are sorted into new, twice, already members and not addresses", () => {
    const d = dirOf();
    const l = inviteList(d, "acme", ["new@x.example", "NEW@x.example", "lena@acme.example", "yuki@acme.example", "nope", "other@x.example"]);
    expect(l).toEqual({ fresh: ["new@x.example", "other@x.example"], repeated: ["new@x.example"], members: ["lena@acme.example", "yuki@acme.example"], invalid: ["nope"] });
  });
  it("are read from the argument with the role and access, and written back the same", () => {
    const d = dirOf();
    const a = parseAccess(d, "acme", "a@x.example, b@x.example role:manager finance:hidden shared:read what");
    expect(a).toEqual({ emails: ["a@x.example", "b@x.example"], role: "manager", access: { finance: "readHidden", shared: "read" }, unknown: ["what"] });
    expect(accessArg(d, "acme", a)).toBe("a@x.example b@x.example role:manager finance:hidden shared:read what");
  });
  it("send only to new people, and wait while an address is wrong or nobody is new", () => {
    const d = dirOf();
    const p = preview(d, "invite", "org:acme", "new@x.example lena@acme.example new@x.example finance:hidden");
    expect(p.effect).toEqual({ org: { op: "invite", orgId: "acme", invite: { emails: ["new@x.example"], role: "user", accessAll: false, access: { finance: "readHidden" } } } });
    expect(p.blocked).toBeUndefined();
    expect(p.now!.map((x) => x.level)).toEqual(["unknown", "unknown"]);
    expect(side(row(p, "new@x.example").to)).toEqual({ level: "unknown", text: "Invited · User" });
    expect(side(row(p, "Finance").to)).toEqual({ level: "unknown", text: "+1 · Without passwords" });
    expect(preview(d, "invite", "org:acme", "lena@acme.example").blocked).toBeDefined();
    expect(preview(d, "invite", "org:acme", "new@x.example oops@").blocked).toBeDefined();
    expect(preview(d, "invite", "org:acme", "").blocked).toBeDefined();
  });
});

describe("the line and the findings", () => {
  it("keeps the argument's case, and names it in the crumb", () => {
    const q = new Query(dirOf(), CORE_VERBS);
    const st = q.compile("acme > new collection Big Money");
    expect(st.verb).toBe("new collection");
    expect(st.arg).toBe("Big Money");
    expect(q.serialize(st)).toBe("acme > new collection Big Money");
  });
  it("send Tomás's finding to his role, with Finance one step down", () => {
    const d = dirOf();
    const f = orgFindings(d, "org:acme").find((x) => x.focus === "member:tomas")!;
    expect(f.action.label).toBe("find.narrow");
    if (!("run" in f.action.act)) throw new Error("the finding should run a line");
    const q = new Query(d, CORE_VERBS);
    const st = q.compile(f.action.act.run);
    expect(q.dir.node((st.segs.at(-1) as { id: string }).id).id).toBe("member:tomas");
    expect(st.verb).toBe("role");
    expect(st.arg).toBe("finance:none");
    expect(f.action.act.run).toBe(verbLine(d, "member:tomas", "role", "finance:none"));
  });
  it("stays a map's finding where the one looking may not change roles", () => {
    const c = structuredClone(DEMO);
    c.orgs.find((o) => o.id === "acme")!.can.manageMembers = false;
    const f = orgFindings(dirOf(c), "org:acme").find((x) => x.focus === "member:tomas")!;
    expect("map" in f.action.act).toBe(true);
  });
});

describe("a confirm goes with the fingerprint that was shown", () => {
  const confirm = { op: OrgOp.ConfirmMember, orgId: "acme", memberId: "tomas", fingerprint: null } as const;
  it("takes the words on screen for that very member, and nothing for another", () => {
    const shown = (o: string, m: string) => (o === "acme" && m === "tomas" ? ["a", "b", "c", "d", "e"] : null);
    expect(withShownFingerprint(confirm, shown)).toEqual({ ...confirm, fingerprint: ["a", "b", "c", "d", "e"] });
    expect(withShownFingerprint({ ...confirm, memberId: "dana" }, shown)).toEqual({ ...confirm, memberId: "dana" });
    const other = { op: OrgOp.RemoveMember, orgId: "acme", memberId: "tomas" } as const;
    expect(withShownFingerprint(other, shown)).toBe(other);
  });
  it("is refused before the backend is asked when no words were shown", async () => {
    const w = new DemoWrites(new DemoBackend());
    w.delay = 0;
    await expect(runOrgWrite(w, confirm)).rejects.toThrow("err.fingerprintNotShown");
    expect(w.calls).toEqual([]);
  });
  it("confirms in the demo with the demo's words, and refuses others", async () => {
    const backend = new DemoBackend();
    const w = new DemoWrites(backend);
    w.delay = 0;
    const words = await w.memberFingerprint("acme", "tomas");
    expect(words).toEqual([...DEMO_FINGERPRINT]);
    expect(words).toHaveLength(5);
    await expect(runOrgWrite(w, { ...confirm, fingerprint: ["turban", "deftly", "anime", "chatroom", "zoom"] })).rejects.toThrow();
    expect((await backend.catalog()).members.find((m) => m.id === "tomas")?.status).toBe("accepted");
    await runOrgWrite(w, { ...confirm, fingerprint: words });
    expect((await backend.catalog()).members.find((m) => m.id === "tomas")?.status).toBe("confirmed");
    await expect(w.memberFingerprint("acme", "nobody")).rejects.toThrow();
  });
});

describe("the demo's writes", () => {
  it("change the catalogue the window reads", async () => {
    const backend = new DemoBackend();
    const w = new DemoWrites(backend);
    w.delay = 0;
    const d = dirOf(await backend.catalog());
    const inv = ready(previewOf(d, CORE_VERBS, "invite", "org:acme", "new@x.example role:manager"));
    if (!("org" in inv.effect)) throw new Error("an invite is an organisation's write");
    await runOrgWrite(w, inv.effect.org);
    const after = await backend.catalog();
    expect(after.members.find((m) => m.email === "new@x.example")).toMatchObject({ role: "manager", status: "invited" });
    const id = await runOrgWrite(w, { op: OrgOp.CreateCollection, orgId: "acme", name: "Big Money" });
    expect((await backend.catalog()).collections.find((c) => c.id === id)?.name).toBe("Big Money");
  });
});
