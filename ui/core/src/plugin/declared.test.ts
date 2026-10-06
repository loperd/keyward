// A plugin's declared places made into the path: the nodes, their homes and
// rows, the pages, the verbs and their effects, the findings about items, the
// lines and the map — and the refusals, by name, of what does not hold.
import { beforeEach, describe, expect, it } from "vitest";
import { registerWords, setLang, text, unregisterWords, type Words, Lang } from "../i18n";
import { Directory, isStep, ResultGroup } from "../path/directory";
import { Query } from "../path/query";
import { CORE_VERBS } from "../verbs/core";
import { type Catalog, type Item, ItemKind, Level } from "../model/types";
import { contributionOf, failedContribution, type DeclaredPlaces, DeclaredKidType, DeclaredBlockType } from "./declared";
import { PreviewKind } from "../verbs/spec";
import { EdgeKind } from "../map/types";

const NOW = new Date("2026-10-01T12:00:00Z");
const key = (id: string, name: string): Item => ({
  id,
  name,
  kind: ItemKind.SshKey,
  subtitle: "SHA256:abc",
  folderId: null,
  orgId: null,
  collectionIds: [],
  uris: [],
  tags: {},
  hasTotp: false,
  passkeys: 0,
  favorite: false,
  deleted: false,
  reprompt: false,
  revised: null,
  passwordRevised: null,
  expires: null,
  reused: 0,
  reuseGroup: null,
});
// A folder called "hosts" takes the word first: the plugin's step must yield.
const catalog: Catalog = { items: [key("k1", "prod key"), key("k2", "staging key")], folders: [{ id: "f1", name: "Hosts" }], orgs: [], collections: [], members: [] };

const WORDS: Words = {
  [Lang.Ru]: { title: "SSH", hosts: "Хосты", keys: "Ключи", check: "Проверить", lede: "Ключи предлагаются хостам без подписи", rejected: "Ключ отклонён", ok: "Пускает", map: "Топология", login: "Логин", sub: "Хостов: {n}" },
  [Lang.En]: { title: "SSH", hosts: "Hosts", keys: "Keys", check: "Check", lede: "Keys are offered to hosts without signing", rejected: "Key rejected", ok: "Gets in", map: "Topology", login: "Login", sub: "Hosts: {n}" },
};

/// What the ssh plugin answers, in small: two hosts, two keys, one refused.
function fixture(): DeclaredPlaces {
  return {
    root: {
      id: "",
      icon: "terminal",
      hue: "cyan",
      title: { key: "title" },
      subtitle: { key: "sub", args: { n: 2 } },
      level: Level.Critical,
      why: { key: "rejected" },
      kids: [{ type: DeclaredKidType.Place, id: "hosts" }, { type: DeclaredKidType.Place, id: "keys" }, { type: DeclaredKidType.Gap }, { type: DeclaredKidType.Place, id: "map" }],
      page: { primary: "check keys", map: true, sections: [{ title: { key: "hosts" }, blocks: [{ type: DeclaredBlockType.Finding, level: Level.Critical, title: { raw: "db-1" }, sub: { key: "rejected" }, to: { place: "host/db-1:22" } }] }] },
    },
    places: [
      { id: "hosts", parent: "", icon: "server", title: { key: "hosts" }, count: 2, level: Level.Critical, wide: true, kids: [{ type: DeclaredKidType.Heading, title: { raw: "prod" } }, { type: DeclaredKidType.Place, id: "host/db-1:22" }, { type: DeclaredKidType.Place, id: "host/api:22" }] },
      { id: "keys", parent: "", icon: "key", title: { key: "keys" }, count: 2, level: Level.Critical, kids: [{ type: DeclaredKidType.Item, id: "k1" }, { type: DeclaredKidType.Item, id: "k2", sub: { key: "ok" } }] },
      { id: "map", parent: "", icon: "map", title: { key: "map" }, level: Level.Critical, map: true },
      {
        id: "host/db-1:22",
        parent: "hosts",
        icon: "server",
        title: { raw: "db-1.prod.example" },
        row_title: { raw: "db-1" },
        subtitle: { raw: "root@ · 22" },
        mono: true,
        level: Level.Critical,
        why: { key: "rejected" },
        short: { key: "rejected" },
        find: { group: ResultGroup.Hosts, kind: "host", words: "db-1.prod.example root" },
        page: {
          primary: "check keys",
          sections: [{ title: { key: "keys" }, blocks: [{ type: DeclaredBlockType.Ref, to: { item: "k1" }, mark: { level: Level.Critical, text: { key: "rejected" } } }, { type: DeclaredBlockType.Field, label: { key: "login" }, value: { raw: "root" }, mono: true }] }],
        },
      },
      { id: "host/api:22", parent: "hosts", icon: "server", title: { raw: "api.prod.example" }, mono: true, level: Level.Healthy, find: { group: ResultGroup.Hosts, kind: "host", words: "api.prod.example" } },
    ],
    marks: [{ item: "k1", level: Level.Critical, why: { key: "rejected" }, short: { key: "rejected" } }],
    lines: [{ from: "host/db-1:22", item: "k1", kind: EdgeKind.Refused, level: Level.Critical, words: { key: "rejected" }, short: { key: "rejected" } }],
    verbs: [
      {
        id: "check keys",
        name: { key: "check" },
        icon: "refresh",
        uses: [
          { on: { place: "" }, action: { op: "check" } },
          { on: { place: "host/db-1:22" }, action: { op: "check", payload: { entry_id: "k1" } } },
          { on: { item: "k1" }, action: { op: "check", payload: { entry_id: "k1" } } },
        ],
        preview: { lede: { key: "lede" }, go: { key: "check" } },
      },
      { id: "forget host", name: { raw: "Forget" }, uses: [{ on: { place: "host/api:22" }, action: { op: "forget", payload: { host: "api" }, confirm: "api" } }], preview: { lede: { raw: "gone" }, go: { raw: "Forget" } } },
    ],
    topology: {
      title: { key: "map" },
      place: { key: "title" },
      lanes: [{ key: "keys" }, { key: "hosts" }],
      pivot: 1,
      points: [{ at: { item: "k1" }, lane: 0 }, { at: { place: "host/db-1:22" }, lane: 1 }, { at: { place: "host/api:22" }, lane: 1 }],
      edges: [{ a: { item: "k1" }, b: { place: "host/db-1:22" }, kind: EdgeKind.Refused, level: Level.Critical, words: { key: "rejected" }, chip: true }],
      findings: [{ level: Level.Critical, text: { raw: "db-1" }, focus: { place: "host/db-1:22" } }],
    },
    refresh_ms: 60000,
  };
}

const ICONS = new Set(["terminal", "server", "key", "map", "refresh", "verb", "cube"]);
const build = (d: DeclaredPlaces = fixture()) => contributionOf("ssh", d, { words: WORDS, icons: ICONS, taken: new Set(CORE_VERBS.map((v) => v.id)) });

beforeEach(() => {
  setLang(Lang.En);
  unregisterWords("ssh");
});

describe("a plugin's declared places", () => {
  it("become nodes under the plugin's root, each at home under its parent", () => {
    const c = build();
    registerWords(c.id, c.words!);
    const dir = new Directory(catalog, [c], { now: NOW });
    expect(dir.kidIds("root")).toContain("plugin:ssh");
    expect(dir.node("ssh:host/db-1:22").home).toEqual(["plugin:ssh", "ssh:hosts", "ssh:host/db-1:22"]);
    expect(dir.node("ssh:keys").home).toEqual(["plugin:ssh", "ssh:keys"]);
    expect(dir.kidIds("plugin:ssh")).toEqual(["ssh:hosts", "ssh:keys", "ssh:map"]);
    expect(dir.kids("plugin:ssh")[2]).toEqual({ gap: true });
    expect(dir.kids("ssh:hosts")[0]).toEqual({ heading: { raw: "prod" } });
    expect(dir.kidIds("ssh:keys")).toEqual(["item:k1", "item:k2"]);
    const k2 = dir.kids("ssh:keys")[1]!;
    expect(isStep(k2) && k2.sub && text(k2.sub)).toBe("Gets in");
    expect(dir.node("ssh:map").map).toEqual({ kind: "topology", anchor: "plugin:ssh" });
    const db = dir.node("ssh:host/db-1:22");
    expect([db.level, text(db.name), text(db.rowName!), db.mono]).toEqual(["critical", "db-1.prod.example", "db-1", true]);
    expect(db.result).toEqual({ group: "hosts", kind: "host", orgId: null, place: ["plugin:ssh", "ssh:hosts"], haystack: "db-1.prod.example root" });
    expect(dir.node("plugin:ssh").hue).toBe("cyan");
  });

  it("speak the plugin's words, in either language", () => {
    const c = build();
    registerWords(c.id, c.words!);
    const dir = new Directory(catalog, [c], { now: NOW });
    expect(text(dir.node("plugin:ssh").sub!)).toBe("Hosts: 2");
    setLang(Lang.Ru);
    expect(text(dir.node("ssh:hosts").name)).toBe("Хосты");
    // A name in any language steps there.
    expect(dir.stepOf("хосты")).toBe("ssh:hosts");
  });

  it("give way to a folder that has the word already", () => {
    const c = build();
    registerWords(c.id, c.words!);
    const dir = new Directory(catalog, [c], { now: NOW });
    expect(dir.node("folder:f1").slug).toBe("hosts");
    expect(dir.node("ssh:hosts").slug).toBe("hosts-2");
    expect(dir.node("plugin:ssh").slug).toBe("ssh");
  });

  it("mark the vault's items and draw lines to them", () => {
    const c = build();
    registerWords(c.id, c.words!);
    const dir = new Directory(catalog, [c], { now: NOW });
    expect(dir.node("item:k1").level).toBe("critical");
    expect(text(dir.node("item:k1").why!)).toBe("Key rejected");
    expect(dir.node("item:k2").level).not.toBe("critical");
    expect(dir.links()).toEqual([expect.objectContaining({ from: "ssh:host/db-1:22", to: "item:k1", kind: "refused", level: "critical" })]);
  });

  it("have pages in the core's vocabulary", () => {
    const c = build();
    registerWords(c.id, c.words!);
    const dir = new Directory(catalog, [c], { now: NOW });
    const host = dir.node("ssh:host/db-1:22").doc!(dir);
    expect(host.hero.place).toEqual(["plugin:ssh", "ssh:hosts"]);
    expect(host.hero.primary).toEqual({ icon: "refresh", label: { ext: "ssh.check" }, act: { verb: "check keys" } });
    expect(host.hero.state).toEqual({ level: "critical", text: { ext: "ssh.rejected" } });
    const [ref, field] = host.sections[0]!.blocks;
    expect(ref).toEqual({ ref: "item:k1", lead: { tile: "node", id: "item:k1" }, title: { raw: "prod key" }, mark: { level: "critical", text: { ext: "ssh.rejected" } } });
    expect(field).toEqual({ field: { ext: "ssh.login" }, value: { raw: "root" }, mono: true });
    const root = dir.node("plugin:ssh").doc!(dir);
    expect(root.hero.more).toEqual([{ icon: "map", label: { ext: "ssh.map" }, act: { map: { kind: "topology", anchor: "plugin:ssh" } } }]);
    expect(root.sections[0]!.blocks[0]).toEqual({ sig: "critical", title: { raw: "db-1" }, sub: { ext: "ssh.rejected" }, go: { go: "ssh:host/db-1:22" } });
    // A place with no page still has its head.
    expect(dir.node("ssh:host/api:22").doc!(dir).hero.title).toEqual({ raw: "api.prod.example" });
  });

  it("bring verbs that apply where declared and ask the backend for the plugin's action", () => {
    const c = build();
    registerWords(c.id, c.words!);
    const dir = new Directory(catalog, [c], { now: NOW });
    const q = new Query(dir, [...CORE_VERBS, ...c.verbs!]);
    const check = c.verbs!.find((v) => v.id === "check keys")!;
    expect(check.applies(dir.node("plugin:ssh"))).toBe(true);
    expect(check.applies(dir.node("item:k1"))).toBe(true);
    expect(check.applies(dir.node("ssh:keys"))).toBe(false);
    expect(q.verbsFor({ segs: [{ id: "plugin:ssh" }], map: null, verb: null, arg: "" }).map((v) => v.id)).toContain("check keys");
    const p = check.preview!(dir, "item:k1", "");
    expect(p).toMatchObject({ kind: "ready", target: "item:k1", go: { ext: "ssh.check" }, effect: { plugin: { plugin: "ssh", op: "check", payload: { entry_id: "k1" } } } });
    expect(check.preview!(dir, "plugin:ssh", "")).toMatchObject({ effect: { plugin: { plugin: "ssh", op: "check", payload: null } } });
  });

  it("hold back an action that asks for a word until it is typed", () => {
    const c = build();
    registerWords(c.id, c.words!);
    const dir = new Directory(catalog, [c], { now: NOW });
    const forget = c.verbs!.find((v) => v.id === "forget host")!;
    const before = forget.preview!(dir, "ssh:host/api:22", "");
    expect(before).toMatchObject({ kind: "ready", danger: true, blocked: { key: "plugin.typeToConfirm" } });
    const after = forget.preview!(dir, "ssh:host/api:22", "api");
    expect(after.kind === PreviewKind.Ready && after.blocked).toBeFalsy();
  });

  it("draw the plugin's map from the graph", () => {
    const c = build();
    registerWords(c.id, c.words!);
    const dir = new Directory(catalog, [c], { now: NOW });
    const m = dir.topology("plugin:ssh");
    expect(m.nodes.map((n) => [n.id, n.lane, n.shape])).toEqual([
      ["item:k1", 0, "ssh"],
      ["ssh:host/db-1:22", 1, "host"],
      ["ssh:host/api:22", 1, "host"],
    ]);
    expect(m.edges).toEqual([{ a: "item:k1", b: "ssh:host/db-1:22", kind: "refused", level: "critical", words: { ext: "ssh.rejected" }, chip: true }]);
    expect(m.findings[0]!.focus).toBe("ssh:host/db-1:22");
    expect(m.pivot).toBe(1);
  });

  it("refuse, by the plugin's name, what does not hold together", () => {
    const spoil = (f: (d: DeclaredPlaces) => void) => {
      const d = fixture();
      f(d);
      return () => build(d);
    };
    expect(spoil((d) => d.places!.push({ ...d.places![0]! }))).toThrow(/"ssh" declares the place "hosts" twice/);
    expect(spoil((d) => (d.places![3]!.parent = "nowhere"))).toThrow(/under "nowhere", which it does not declare/);
    expect(spoil((d) => (d.places![0]!.parent = "host/db-1:22"))).toThrow(/under itself/);
    expect(spoil((d) => d.root.kids!.push({ type: DeclaredKidType.Place, id: "ghost" }))).toThrow(/"ghost", which it does not declare/);
    expect(spoil((d) => (d.places![0]!.title = { key: "nope" }))).toThrow(/the word "nope" .* which its ru dictionary lacks/);
    expect(spoil((d) => (d.places![0]!.icon = "rocket"))).toThrow(/the icon "rocket" .* which the window does not have/);
    expect(spoil((d) => (d.places![0]!.level = "fine" as never))).toThrow(/the level "fine"/);
    expect(spoil((d) => (d.verbs![0]!.id = "lock"))).toThrow(/already the window's or another plugin's/);
    expect(spoil((d) => (d.root.page!.primary = "ghost"))).toThrow(/offering the verb "ghost", which it does not declare/);
    expect(spoil((d) => (d.places![4]!.page = { primary: "check keys", sections: [] }))).toThrow(/which does not apply there/);
    expect(spoil((d) => delete d.topology)).toThrow(/and no map/);
    expect(spoil((d) => (d.topology!.points[0]!.lane = 7))).toThrow(/in lane 7 of 2/);
    expect(spoil((d) => d.topology!.points.shift())).toThrow(/which is not on the map/);
    expect(spoil((d) => (d.root.hue = "pink"))).toThrow(/the hue "pink"/);
    expect(spoil((d) => (d.root.id = "root"))).toThrow(/a root that is not the root/);
    expect(() => contributionOf("ssh", fixture(), { icons: ICONS })).toThrow(/brings no dictionary/);
    expect(() => contributionOf("Bad Id", fixture(), { words: WORDS })).toThrow(/not a word of the path/);
  });

  it("stand loud, with the reason, where a plugin did not answer", () => {
    const c = failedContribution("kube", "Kubernetes", "cube", "the cluster is gone");
    const dir = new Directory(catalog, [c], { now: NOW });
    const n = dir.node("plugin:kube");
    expect(n.level).toBe("warning");
    expect(text(n.why!)).toContain("the cluster is gone");
    expect(n.doc!(dir).hero.state!.level).toBe("warning");
  });
});
