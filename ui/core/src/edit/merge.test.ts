// A merge as a person decides it, and as the demo carries it out: the kept
// record's name and fields stand, what it lacks is taken, what it holds
// differently stays until a person says otherwise, and the others go to the
// trash.
import { beforeEach, describe, expect, it } from "vitest";
import { DEMO } from "../demo";
import { DemoBackend } from "../demo-backend";
import { Call, DemoWrites } from "../demo-writes";
import { Lang, setLang, text } from "../i18n";
import { type Item, ItemKind, SecretField } from "../model/types";
import { MergeField, type MergeComparison, type MergeSlot } from "../writes";
import { MergeChoice, RowState, choose, draftMerge, mergeGroup, mergeProblem, planOf, planRefusal, rename, slotLabel } from "./merge";

// The drafts below are drawn when the file is read, so the language is set
// before them too.
setLang(Lang.En);
beforeEach(() => setLang(Lang.En));
const label = (s: MergeSlot) => text(slotLabel(s));
const base = DEMO.items.find((i) => i.id === "github")!;
const login = (o: Partial<Item>): Item => ({ ...base, uris: [], orgId: null, collectionIds: [], folderId: null, reused: 0, reuseGroup: null, hasTotp: false, passkeys: 0, ...o });
const second = login({ id: "second", name: "second icloud", subtitle: "me@icloud.com" });
const apple = login({ id: "apple", name: "appleid.icloud.com", subtitle: "me@icloud.com", uris: ["https://appleid.apple.com"] });
const group = [second, apple];

/// The comparison the backend gives for the two: one login, two passwords,
/// a code only in the other, a PIN each with a different value.
const CMP: MergeComparison = {
  rows: [
    { slot: { field: MergeField.Username }, secret: false, holders: [{ itemId: "second", group: 0 }, { itemId: "apple", group: 0 }] },
    { slot: { field: MergeField.Password }, secret: true, holders: [{ itemId: "second", group: 0 }, { itemId: "apple", group: 1 }] },
    { slot: { field: MergeField.Totp }, secret: true, holders: [{ itemId: "apple", group: 0 }] },
    { slot: { field: MergeField.Custom, name: "PIN" }, secret: true, holders: [{ itemId: "second", group: 0 }, { itemId: "apple", group: 1 }] },
    { slot: { field: MergeField.Passkeys }, secret: false, holders: [{ itemId: "apple", group: 0 }] },
  ],
};

describe("a merge's first state", () => {
  const d = draftMerge(CMP, "second", group, label);
  const line = (key: string) => d.lines.find((l) => l.key === key)!;

  it("keeps the kept record's own and takes only what it lacks", () => {
    expect(line("username").state).toBe(RowState.Same);
    expect(line("password").state).toBe(RowState.Differs);
    expect(line("password").offers[0]!.choice).toBe(MergeChoice.Drop);
    expect(line("custom:pin").offers[0]!.choice).toBe(MergeChoice.Drop);
    expect(line("totp").state).toBe(RowState.Missing);
    expect(line("totp").offers[0]!.choice).toBe(MergeChoice.Fill);
    expect(line("passkeys").offers[0]!.choice).toBe(MergeChoice.Fill);
    expect(planOf(d)).toEqual({
      keeper: "second",
      others: ["apple"],
      takes: [
        { from: "apple", slot: { field: MergeField.Totp }, asName: null },
        { from: "apple", slot: { field: MergeField.Passkeys }, asName: null },
      ],
    });
  });

  it("names a value kept beside the kept one's after its field and its record", () => {
    expect(line("custom:pin").offers[0]!.name).toBe("PIN (appleid.icloud.com)");
    expect(line("password").offers[0]!.name).toBe("Password (appleid.icloud.com)");
  });

  it("starts again from the other record when that one is kept", () => {
    const other = draftMerge(CMP, "apple", group, label);
    expect(other.others).toEqual(["second"]);
    expect(other.lines.find((l) => l.key === "totp")).toMatchObject({ state: RowState.Same, offers: [] });
  });
});

describe("a person's choices", () => {
  const d0 = draftMerge(CMP, "second", group, label);

  it("put one field in place of the kept one's, and keep another beside it", () => {
    let d = choose(d0, "password", 1, MergeChoice.Fill);
    d = choose(d, "custom:pin", 1, MergeChoice.Beside);
    d = rename(d, "custom:pin", 1, "Apple PIN");
    expect(mergeProblem(d, CMP)).toBeNull();
    expect(planOf(d).takes).toEqual([
      { from: "apple", slot: { field: MergeField.Password }, asName: null },
      { from: "apple", slot: { field: MergeField.Totp }, asName: null },
      { from: "apple", slot: { field: MergeField.Custom, name: "PIN" }, asName: "Apple PIN" },
      { from: "apple", slot: { field: MergeField.Passkeys }, asName: null },
    ]);
    expect(planRefusal(planOf(d))).toBeNull();
  });

  it("refuse a name the kept record has, an empty one, and one given twice", () => {
    const beside = choose(d0, "custom:pin", 1, MergeChoice.Beside);
    expect(mergeProblem(rename(beside, "custom:pin", 1, "pin"), CMP)).toEqual({ key: "err.mergeNameTaken", args: { name: "pin" } });
    expect(mergeProblem(rename(beside, "custom:pin", 1, "  "), CMP)).toEqual({ key: "err.mergeNeedName" });
    const two = rename(choose(rename(beside, "custom:pin", 1, "Old"), "password", 1, MergeChoice.Beside), "password", 1, "old");
    expect(mergeProblem(two, CMP)).toEqual({ key: "err.mergeNameTwice" });
  });

  it("fill a field with one value only", () => {
    const three = [...group, login({ id: "third", name: "iCloud", subtitle: "me@icloud.com" })];
    const cmp: MergeComparison = { rows: [{ slot: { field: MergeField.Totp }, secret: true, holders: [{ itemId: "apple", group: 0 }, { itemId: "third", group: 1 }] }] };
    let d = draftMerge(cmp, "second", three, label);
    expect(d.lines[0]!.offers.map((o) => o.choice)).toEqual([MergeChoice.Fill, MergeChoice.Drop]);
    d = choose(d, "totp", 1, MergeChoice.Fill);
    expect(d.lines[0]!.offers.map((o) => o.choice)).toEqual([MergeChoice.Drop, MergeChoice.Fill]);
  });
});

describe("a plan", () => {
  it("is refused when it cannot be carried out", () => {
    const slot = { field: MergeField.Password } as const;
    expect(planRefusal({ keeper: "a", others: [], takes: [] })).toBe("err.mergeNothing");
    expect(planRefusal({ keeper: "a", others: ["a"], takes: [] })).toBe("err.mergeTwice");
    expect(planRefusal({ keeper: "a", others: ["b"], takes: [{ from: "c", slot, asName: null }] })).toBe("err.mergeForeignTake");
    expect(planRefusal({ keeper: "a", others: ["b", "c"], takes: [{ from: "b", slot, asName: null }, { from: "c", slot, asName: null }] })).toBe("err.mergeSlotTwice");
  });
});

describe("the group a merge is offered for", () => {
  it("is the record and its copies", () => {
    const cat = { ...DEMO, items: [...DEMO.items, second, apple] };
    expect(mergeGroup(second, cat).map((i) => i.id)).toEqual(["second", "apple"]);
  });
});

describe("the demo's merge", () => {
  it("compares, carries the chosen values into the kept record and sends the copy to the trash", async () => {
    const backend = new DemoBackend();
    const writes = new DemoWrites(backend);
    writes.delay = 0;
    backend.mutate((c) => c.items.push({ ...second, hasTotp: false }, { ...apple, hasTotp: true, passkeys: 1 }));

    const cmp = await writes.compareForMerge(["second", "apple"]);
    expect(JSON.stringify(cmp)).not.toContain("demo-");
    let d = draftMerge(cmp, "second", group, label);
    d = choose(d, "password", 1, MergeChoice.Beside);
    await writes.merge(planOf(d));

    expect(writes.calls.at(-1)).toBe(`${Call.Merge} second apple password=Password (appleid.icloud.com) totp passkeys`);
    const kept = await backend.item("second");
    expect(kept.item).toMatchObject({ name: "second icloud", hasTotp: true, passkeys: 1, uris: ["https://appleid.apple.com"] });
    expect(kept.item.kind).toBe(ItemKind.Login);
    const beside = kept.fields.find((f) => f.label === "Password (appleid.icloud.com)")!;
    expect(beside.value).toBeNull();
    const shown = await backend.reveal(beside.secret!);
    expect(shown.value).toBe("demo-password-apple");
    shown.drop();
    const own = await backend.reveal({ itemId: "second", field: SecretField.Password });
    expect(own.value).toBe("demo-password-second");
    own.drop();
    const totp = await backend.reveal({ itemId: "second", field: SecretField.Totp });
    expect(totp.value).toBe("demo-totp-apple");
    totp.drop();
    expect((await backend.catalog()).items.find((i) => i.id === "apple")!.deleted).toBe(true);
  });
});
