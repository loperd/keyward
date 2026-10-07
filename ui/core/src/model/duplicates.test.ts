// "KuCoin ALEX: the password matches KuCoin ALEX" told a person nothing:
// two records of the same name, and no word of which or where. A copy of the
// same record is a duplicate (housekeeping), a password shared with another
// record a reuse (a risk), and a partner with the same name is named with its
// place.
import { describe, expect, it } from "vitest";
import { DEMO, DEMO_NOW } from "../demo";
import { Lang, setLang, text } from "../i18n";
import { Directory } from "../path/directory";
import { duplicatesOf, itemState, reusedWith, settledSignals } from "./reasons";
import { Level, type Catalog, type Item } from "./types";

const base = DEMO.items.find((i) => i.id === "github")!;
const make = (o: Partial<Item>): Item => ({ ...base, uris: [], orgId: null, collectionIds: [], passwordRevised: null, revised: null, reused: 0, reuseGroup: null, ...o });

function vault(items: Item[]): Catalog {
  return { ...DEMO, items: [...DEMO.items.filter((i) => i.reuseGroup === null), ...items] };
}

describe("a password shared only with a copy of the same record", () => {
  const a = make({ id: "k1", name: "KuCoin ALEX", subtitle: "alex@x", orgId: null, collectionIds: [], folderId: "work", reused: 1, reuseGroup: 7 });
  const b = make({ id: "k2", name: "KuCoin ALEX", subtitle: "alex@x", orgId: "acme", collectionIds: ["finance"], folderId: null, reused: 1, reuseGroup: 7 });
  const cat = vault([a, b]);

  it("is a duplicate, a warning, not a critical reuse", () => {
    expect(duplicatesOf(a, cat).map((i) => i.id)).toEqual(["k2"]);
    expect(reusedWith(a, cat)).toEqual([]);
    expect(settledSignals(a, cat, DEMO_NOW).map((s) => s.key)).toContain("sig.duplicate");
    expect(settledSignals(a, cat, DEMO_NOW).map((s) => s.key)).not.toContain("sig.reused");
    expect(itemState(a, cat, DEMO_NOW).level).toBe(Level.Warning);
  });
  it("says where the copy is", () => {
    setLang(Lang.Ru);
    expect(text(itemState(a, cat, DEMO_NOW).why)).toBe("Дубликат: та же запись в Acme › Finance");
    expect(text(itemState(b, cat, DEMO_NOW).why)).toBe("Дубликат: та же запись в Work");
  });
  it("draws the item without a critical mark", () => {
    const d = new Directory(cat);
    expect(d.node("item:k1").level).toBe(Level.Warning);
  });
});

describe("a password shared with another record as well as a copy", () => {
  const a = make({ id: "k1", name: "KuCoin ALEX", subtitle: "alex@x", folderId: "work", reused: 2, reuseGroup: 7 });
  const b = make({ id: "k2", name: "KuCoin ALEX", subtitle: "alex@x", folderId: "home", reused: 2, reuseGroup: 7 });
  const c = make({ id: "k3", name: "Binance", subtitle: "alex@x", folderId: "work", reused: 2, reuseGroup: 7 });
  const cat = vault([a, b, c]);
  it("is still a critical reuse, named by the other record", () => {
    setLang(Lang.Ru);
    expect(itemState(a, cat, DEMO_NOW).level).toBe(Level.Critical);
    expect(text(itemState(a, cat, DEMO_NOW).why)).toBe("Пароль совпадает с Binance");
    expect(settledSignals(a, cat, DEMO_NOW).map((s) => s.key)).toEqual(expect.arrayContaining(["sig.reused", "sig.duplicate"]));
  });
});

describe("two different records with the same name", () => {
  const a = make({ id: "k1", name: "KuCoin ALEX", subtitle: "alex@x", folderId: "work", reused: 1, reuseGroup: 7 });
  const b = make({ id: "k2", name: "KuCoin ALEX", subtitle: "trader@y", folderId: "home", reused: 1, reuseGroup: 7 });
  const cat = vault([a, b]);
  it("names the other one with its place, so the two can be told apart", () => {
    setLang(Lang.Ru);
    expect(itemState(a, cat, DEMO_NOW).level).toBe(Level.Critical);
    expect(text(itemState(a, cat, DEMO_NOW).why)).toBe("Пароль совпадает с KuCoin ALEX · Дом");
  });
});

describe("one login kept twice under different names", () => {
  // The case that started the merge: "second icloud" and
  // "appleid.icloud.com" are one Apple ID.
  const a = make({ id: "s", name: "second icloud", subtitle: "me@icloud.com", uris: [], reused: 1, reuseGroup: 9 });
  const b = make({ id: "a", name: "appleid.icloud.com", subtitle: "me@icloud.com", uris: ["https://appleid.apple.com"], reused: 1, reuseGroup: 9 });
  const cat = vault([a, b]);
  it("is a duplicate: one brand in the name of one and the address of the other", () => {
    expect(duplicatesOf(a, cat).map((i) => i.id)).toEqual(["a"]);
    expect(duplicatesOf(b, cat).map((i) => i.id)).toEqual(["s"]);
    expect(itemState(a, cat, DEMO_NOW).level).toBe(Level.Warning);
  });
  it("offers the merge on the item", () => {
    expect(new Directory(cat).node("item:s").copies).toBe(1);
  });
});

describe("a copy left with the password before the last change", () => {
  const a = make({ id: "n", name: "GitHub", subtitle: "alex", uris: ["https://github.com/login"], reused: 0, reuseGroup: null });
  const b = make({ id: "o", name: "github.com", subtitle: "Alex ", uris: [], reused: 0, reuseGroup: null });
  it("is a duplicate all the same: one service, one login", () => {
    expect(duplicatesOf(a, vault([a, b])).map((i) => i.id)).toEqual(["o"]);
  });
  it("is not one without a login unless the password is the same", () => {
    const x = make({ id: "x", name: "GitHub", subtitle: null, reuseGroup: null });
    const y = make({ id: "y", name: "GitHub", subtitle: null, reuseGroup: null });
    expect(duplicatesOf(x, vault([x, y]))).toEqual([]);
    const z = make({ id: "z", name: "GitHub", subtitle: null, reuseGroup: 4, reused: 1 });
    const w = make({ id: "w", name: "github", subtitle: null, reuseGroup: 4, reused: 1 });
    expect(duplicatesOf(z, vault([z, w])).map((i) => i.id)).toEqual(["w"]);
  });
});

describe("brands", () => {
  it("are the host's own name without its zone", async () => {
    const { brandOf } = await import("./reasons");
    expect(brandOf("appleid.icloud.com")).toBe("icloud");
    expect(brandOf("www.bbc.co.uk")).toBe("bbc");
    expect(brandOf("localhost")).toBeNull();
    expect(brandOf("10.0.0.1")).toBeNull();
  });
});
