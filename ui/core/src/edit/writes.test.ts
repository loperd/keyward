import { beforeEach, describe, expect, it } from "vitest";
import { DEMO, DEMO_NOW } from "../demo";
import { DemoBackend, demoContributions } from "../demo-backend";
import { DemoWrites, generatePassphrase, generatePassword, Call } from "../demo-writes";
import { setLang, Lang } from "../i18n";
import { type Catalog, ItemKind, SecretField } from "../model/types";
import { Directory } from "../path/directory";
import { Query } from "../path/query";
import { PathStore } from "../path/store";
import { CORE_VERBS, previewOf } from "../verbs/core";
import { withWriteVerbs } from "../verbs/writes";
import { detailOf, draftOf, fillSecrets, formForNew, typedSlots, formFromDetail, itemOf, kindOfVerb, placeOptions, placementOf, problems, secretOf, switchKind, type Form } from "./draft";
import { land, landingReady } from "./landing";
import { GeneratorKind } from "../writes";
import { PreviewKind } from "../verbs/spec";

const contribs = demoContributions();
const dirOf = (c: Catalog = DEMO) => new Directory(c, contribs, { now: DEMO_NOW });
const withWrites = (d = dirOf()) => new Query(d, withWriteVerbs(CORE_VERBS));
const without = (d = dirOf()) => new Query(d, CORE_VERBS);
const ids = (q: Query, node: string | null) => q.verbsFor({ segs: node ? q.dir.node(node).home.map((id) => ({ id })) : [], map: null, verb: null, arg: "" }).map((v) => v.id);
const field = (f: Form, key: string) => draftOf(f).fields.find((x) => "key" in x && x.key === key);

beforeEach(() => setLang(Lang.Ru));

describe("a draft", () => {
  it("keeps a stored secret it was not given, and never holds its value", async () => {
    const d = await new DemoBackend().item("aws");
    const f = formFromDetail(d);
    expect(f.secrets.password).toEqual({ stored: true, input: null });
    expect(JSON.stringify(f)).not.toContain("demo-password");
    expect(field(f, "password")).toEqual({ key: "password", secret: { keep: true } });
    expect(field(f, "totp")).toEqual({ key: "totp", secret: { keep: true } });
    expect(field(f, "username")).toEqual({ key: "username", value: "alex.morgan" });
    expect(draftOf(f).uris).toEqual(["https://console.aws.amazon.com"]);
    // The custom field the vault had stays the custom field it is.
    expect(draftOf(f).fields).toContainEqual({ custom: "Аккаунт", value: "4417 2290 1186", hidden: false });
  });

  it("sends a typed value, clears on asking, and keeps on an empty replace", async () => {
    const f = formFromDetail(await new DemoBackend().item("aws"));
    const set = (input: Form["secrets"][string]["input"]) => ({ ...f, secrets: { ...f.secrets, password: { stored: true, input } } });
    expect(field(set({ set: "new-one" }), "password")).toEqual({ key: "password", secret: { set: "new-one" } });
    expect(field(set({ clear: true }), "password")).toEqual({ key: "password", secret: { clear: true } });
    expect(field(set({ set: "" }), "password")).toEqual({ key: "password", secret: { keep: true } });
    // Nothing is sent for a secret that is not stored and was not typed.
    expect(secretOf({ stored: false, input: null })).toBeNull();
    expect(secretOf({ stored: false, input: { clear: true } })).toBeNull();
    expect(secretOf({ stored: false, input: { set: "x" } })).toEqual({ set: "x" });
  });

  it("holds only a marker for a secret being typed; its value joins at the save", async () => {
    const f = formFromDetail(await new DemoBackend().item("aws"));
    const typing = { ...f, secrets: { ...f.secrets, password: { stored: true, input: { set: "" } } }, notes: { stored: false, input: { set: "" } } };
    expect(typedSlots(typing).sort()).toEqual(["notes", "password"]);
    expect(typedSlots(f)).toEqual([]);
    const filled = fillSecrets(typing, new Map([["password", "from-the-field"], ["notes", ""], ["totp", "ignored"]]));
    expect(field(filled, "password")).toEqual({ key: "password", secret: { set: "from-the-field" } });
    // A slot not being typed into takes nothing, whatever is handed.
    expect(field(filled, "totp")).toEqual({ key: "totp", secret: { keep: true } });
    expect(draftOf(filled).notes).toEqual({ clear: true });
  });

  it("reads a card's expiry and an identity's name into the draft's fields", async () => {
    const b = new DemoBackend();
    const card = formFromDetail(await b.item("stripe"));
    expect(card.values.expMonth).toBe("12");
    expect(card.values.expYear).toBe("2026");
    expect(card.secrets.number).toEqual({ stored: true, input: null });
    const who = formFromDetail(await b.item("identity"));
    expect([who.values.firstName, who.values.lastName]).toEqual(["Alex", "Morgan"]);
  });

  it("asks for a name, and for a collection in an organisation", () => {
    const f = formForNew(ItemKind.Login, { orgId: null, folderId: null, collectionIds: [] });
    expect(problems(f)).toEqual(["edit.needName"]);
    expect(() => draftOf(f)).toThrow(/cannot be saved/);
    expect(problems({ ...f, name: "x", place: { orgId: "acme", folderId: null, collectionIds: [] } })).toEqual(["edit.needCollection"]);
  });

  it("keeps what two kinds share when the kind is switched", () => {
    const f = { ...formForNew(ItemKind.Login, { orgId: null, folderId: "work", collectionIds: [] }, "Bank"), values: { username: "u", password: "" } };
    const c = switchKind(f, ItemKind.Card);
    expect(c.name).toBe("Bank");
    expect(c.place.folderId).toBe("work");
    expect(Object.keys(c.secrets).sort()).toEqual(["code", "number"]);
    expect(switchKind(c, ItemKind.Login).kind).toBe("login");
  });

  it("reads back as the page a sync would draw", async () => {
    const d = await new DemoBackend().item("aws");
    const f = formFromDetail(d);
    const draft = draftOf({ ...f, name: "AWS — prod", values: { ...f.values, username: "ops" } });
    const it = itemOf(draft, d.item);
    expect(it.subtitle).toBe("ops");
    expect(it.hasTotp).toBe(true);
    const back = detailOf(draft, it, d);
    expect(back.fields.map((x) => x.key)).toEqual(["username", "password", "totp", null]);
    expect(back.fields.find((x) => x.key === "password")!.value).toBeNull();
  });
});

describe("the verbs of writes", () => {
  it("are not offered without writes", () => {
    const q = without();
    expect(ids(q, "item:aws")).not.toContain("edit");
    expect(ids(q, "folder:work")).not.toContain("new");
    expect(ids(q, null)).not.toContain("new folder");
  });

  it("are offered where they work", () => {
    const q = withWrites();
    expect(ids(q, "item:aws")).toContain("edit");
    expect(ids(q, "folder:work")).toEqual(expect.arrayContaining(["new", "new login", "new card", "new folder", "rename", "delete"]));
    expect(ids(q, null)).toEqual(expect.arrayContaining(["new", "new folder"]));
    expect(ids(q, "collection:finance")).toContain("new note");
    expect(ids(q, "collection:finance")).not.toContain("new folder");
    expect(ids(q, "member:dana")).not.toContain("new");
  });

  it("is not offered on an item in the trash", () => {
    const c = structuredClone(DEMO);
    c.items.find((i) => i.id === "aws")!.deleted = true;
    const q = withWrites(dirOf(c));
    expect(ids(q, "item:aws")).not.toContain("edit");
    expect(ids(q, "item:aws")).not.toContain("new");
  });

  it("names the kind a creating verb makes", () => {
    expect(kindOfVerb("new")).toBe("login");
    expect(kindOfVerb("new ssh")).toBe("ssh_key");
    expect(kindOfVerb("new folder")).toBeUndefined();
    expect(kindOfVerb(null)).toBeUndefined();
  });

  it("previews a folder's rename and refuses an empty or a taken name", () => {
    const q = withWrites();
    const p = (arg: string) => previewOf(q.dir, q.verbs, "rename", "folder:work", arg);
    const ok = p("Projects");
    expect(ok.kind === PreviewKind.Ready && ok.effect).toEqual({ folder: { op: "rename", id: "work", name: "Projects" } });
    expect(ok.kind === PreviewKind.Ready && ok.blocked).toBeFalsy();
    const empty = p("");
    expect(empty.kind === PreviewKind.Ready && empty.blocked).toEqual({ key: "verb.folder.needName" });
    const taken = p("Дом");
    expect(taken.kind === PreviewKind.Ready && taken.blocked).toEqual({ key: "verb.folder.taken", args: { name: "Дом" } });
  });

  it("previews a folder's deletion: its items stay, without a folder", () => {
    const q = withWrites();
    const p = previewOf(q.dir, q.verbs, "delete", "folder:work", "");
    if (p.kind !== PreviewKind.Ready) throw new Error(p.kind);
    expect(p.effect).toEqual({ folder: { op: "delete", id: "work" } });
    expect(p.danger).toBe(true);
    expect(p.changes!.rows).toHaveLength(1 + q.dir.kidIds("folder:work").length);
  });

  it("keeps a collection's own rename where both have one", () => {
    const q = withWrites();
    const p = previewOf(q.dir, q.verbs, "rename", "collection:finance", "Money");
    expect(p.kind === PreviewKind.Ready && p.effect).toMatchObject({ org: { op: "renameCollection", id: "finance" } });
  });

  it("makes a new folder's preview from the line's argument, its case kept", () => {
    const q = withWrites();
    const st = q.compile("personal > new folder Side Projects");
    expect(st.verb).toBe("new folder");
    expect(st.arg).toBe("Side Projects");
    const p = previewOf(q.dir, q.verbs, st.verb!, "personal", st.arg);
    expect(p.kind === PreviewKind.Ready && p.effect).toEqual({ folder: { op: "create", name: "Side Projects" } });
  });
});

describe("a new item's place", () => {
  it("is the place the line stands in", () => {
    const d = dirOf();
    expect(placementOf(d, null)).toEqual({ orgId: null, folderId: null, collectionIds: [] });
    expect(placementOf(d, "personal")).toEqual({ orgId: null, folderId: null, collectionIds: [] });
    expect(placementOf(d, "folder:work")).toEqual({ orgId: null, folderId: "work", collectionIds: [] });
    expect(placementOf(d, "collection:finance")).toEqual({ orgId: "acme", folderId: null, collectionIds: ["finance"] });
    // An organisation's own page: its first collection one may write to.
    expect(placementOf(d, "org:acme")).toEqual({ orgId: "acme", folderId: null, collectionIds: ["platform"] });
    // An item: beside it.
    expect(placementOf(d, "item:aws")).toEqual({ orgId: null, folderId: "work", collectionIds: [] });
    expect(placementOf(d, "item:travel")).toEqual({ orgId: "acme", folderId: null, collectionIds: ["finance"] });
  });

  it("can be moved only within its owner once it exists", () => {
    const d = dirOf();
    const mine = placeOptions(d, { orgId: null }).map((o) => o.value);
    expect(mine).toEqual(["p", "f:work", "f:home", "f:keys"]);
    const acme = placeOptions(d, { orgId: "acme" }).map((o) => o.value);
    expect(acme.every((v) => v.startsWith("c:acme:"))).toBe(true);
    expect(placeOptions(d).length).toBe(mine.length + placeOptions(d, { orgId: "acme" }).length + placeOptions(d, { orgId: "globex" }).length);
  });

  it("carries a name typed after the verb", () => {
    expect(formForNew(ItemKind.Card, { orgId: null, folderId: "work", collectionIds: [] }, "Visa").name).toBe("Visa");
  });
});

describe("the demo's writes", () => {
  const setup = () => {
    const b = new DemoBackend();
    const w = new DemoWrites(b);
    w.delay = 0;
    return { b, w };
  };

  it("create an item that the next catalogue has, and the window steps onto it", async () => {
    const { b, w } = setup();
    const before = new Directory(await b.catalog(), contribs, { now: DEMO_NOW });
    const store = new PathStore(withWrites(before), "personal › work > new login");
    const f = { ...formForNew(ItemKind.Login, placementOf(before, "folder:work"), "Bank — personal"), values: { username: "me@bank.example" }, secrets: { password: { stored: false, input: { set: "typed-secret" } }, totp: { stored: false, input: null } } };
    const id = await w.create(draftOf(f));
    const landing = { id: `item:${id}`, after: before };
    // Not from the graph the save was asked under.
    expect(landingReady(landing, before)).toBe(false);
    const after = new Directory(await b.catalog(), contribs, { now: DEMO_NOW });
    store.rebase(withWrites(after));
    expect(land(landing, after, store)).toBe(true);
    expect(store.object()).toBe(`item:${id}`);
    expect(store.get().state.verb).toBeNull();
    expect(store.get().line).toBe("personal › work › bank-personal");
    const it = after.node(`item:${id}`).item!;
    expect([it.subtitle, it.folderId, it.hasTotp]).toEqual(["me@bank.example", "work", false]);
    // The typed secret is what the demo reveals; the detail holds a reference.
    const d = await b.item(id);
    expect(d.fields.find((x) => x.key === "password")).toMatchObject({ value: null, secret: { itemId: id, field: "password" } });
    expect((await b.reveal({ itemId: id, field: SecretField.Password })).value).toBe("typed-secret");
    expect(w.calls.join("\n")).not.toContain("typed-secret");
  });

  it("update an item, keeping what the draft kept", async () => {
    const { b, w } = setup();
    const f = formFromDetail(await b.item("aws"));
    await w.update("aws", draftOf({ ...f, name: "AWS — prod", values: { ...f.values, username: "ops" } }));
    const it = (await b.catalog()).items.find((i) => i.id === "aws")!;
    expect([it.name, it.subtitle]).toEqual(["AWS — prod", "ops"]);
    expect((await b.reveal({ itemId: "aws", field: SecretField.Password })).value).toBe("demo-password-aws");
  });

  it("refuse when told to, and change nothing", async () => {
    const { b, w } = setup();
    w.failNext = Call.Update;
    const f = formFromDetail(await b.item("aws"));
    await expect(w.update("aws", draftOf({ ...f, name: "x" }))).rejects.toThrow();
    expect((await b.catalog()).items.find((i) => i.id === "aws")!.name).toBe("AWS — production");
  });

  it("change folders; a deleted folder's items stay without one", async () => {
    const { b, w } = setup();
    const id = await w.createFolder("Side");
    await w.renameFolder(id, "Side projects");
    expect((await b.catalog()).folders.find((x) => x.id === id)!.name).toBe("Side projects");
    await w.deleteFolder("work");
    const c = await b.catalog();
    expect(c.folders.some((x) => x.id === "work")).toBe(false);
    expect(c.items.find((i) => i.id === "aws")!.folderId).toBeNull();
  });

  it("generate a password of every set asked for, and a passphrase", async () => {
    for (let i = 0; i < 20; i++) {
      const p = generatePassword({ kind: GeneratorKind.Password, length: 12, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguous: true });
      expect(p).toHaveLength(12);
      expect(p).toMatch(/[A-Z]/);
      expect(p).toMatch(/[a-z]/);
      expect(p).toMatch(/[0-9]/);
      expect(p).not.toMatch(/[l1O0I]/);
    }
    expect(() => generatePassword({ kind: GeneratorKind.Password, length: 12, upper: false, lower: false, digits: false, symbols: false, avoidAmbiguous: false })).toThrow();
    expect(generatePassphrase({ kind: GeneratorKind.Passphrase, words: 4, separator: "-", capitalize: true, number: false }).split("-")).toHaveLength(4);
    const { w } = setup();
    const g = await w.generate({ kind: GeneratorKind.Password, length: 16, upper: true, lower: true, digits: true, symbols: false, avoidAmbiguous: false });
    expect(g.value).toHaveLength(16);
    g.drop();
    expect(() => g.value).toThrow(/dropped/);
  });
});

describe("an edit answered in place", () => {
  it("leaves no step of its own in the history", () => {
    const store = new PathStore(withWrites(), "personal › work › aws-production");
    store.verb("edit");
    expect(store.get().state.verb).toBe("edit");
    store.settle();
    expect(store.get().line).toBe("personal › work › aws-production");
    expect(store.get().canBack).toBe(false);
  });
});
