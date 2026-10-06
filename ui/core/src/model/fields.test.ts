// Real vaults carry fields the demo does not: a yes/no field, a linked field,
// a site saved without a scheme. One such item once took the whole window
// down ("no words for the field"); these keep every shape the backends send
// drawable, in both languages.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { DEMO } from "../demo";
import { LANGS, setLang, text, type Text, Lang } from "../i18n";
import { Directory } from "../path/directory";
import { buildDoc, fieldLabel } from "../doc/build";
import { type Field, type ItemDetail, ItemKind, SecretField } from "./types";
import { customValue, siteHost } from "./fields";

const field = (key: string | null, label: string, value: string | null): Field => ({ key, label, value, secret: null, mono: false });

describe("custom fields", () => {
  it("say yes or no for a checkbox, under the person's own name", () => {
    setLang(Lang.Ru);
    expect(text(fieldLabel(field("checkbox", "Рабочий", "true")))).toBe("Рабочий");
    expect(text(customValue(field("checkbox", "x", "true"))!)).toBe("Да");
    expect(text(customValue(field("checkbox", "x", "false"))!)).toBe("Нет");
    expect(() => customValue(field("checkbox", "x", "maybe"))).toThrow();
  });
  it("name what a linked field points at, and show a foreign number as it is", () => {
    setLang(Lang.En);
    expect(text(customValue(field("link:101", "Pin", null))!)).toBe("→ Password");
    expect(text(customValue(field("link:418", "Who", null))!)).toBe("→ Full name");
    expect(text(customValue(field("link:999", "New", null))!)).toBe("→ #999");
    expect(text(customValue(field("link:none", "Empty", null))!)).toBe("Pick a field");
  });
});

describe("a site's address", () => {
  it("reads a host with or without a scheme, and none from what is not an address", () => {
    expect(siteHost("https://console.aws.amazon.com/x")).toBe("console.aws.amazon.com");
    expect(siteHost("example.com")).toBe("example.com");
    expect(siteHost("androidapp://com.example.app")).toBe("com.example.app");
    expect(siteHost("^https://.*\\.example\\.com$")).toBeNull();
  });
});

describe("an item with every field shape the daemon sends", () => {
  it("is drawn without throwing, in every language", () => {
    const login = DEMO.items.find((i) => i.kind === ItemKind.Login)!;
    const it = { ...login, uris: ["gitlab.example.com", "^regex$"] };
    const catalog = { ...DEMO, items: DEMO.items.map((i) => (i.id === it.id ? it : i)) };
    const detail: ItemDetail = {
      item: it,
      fields: [
        field("username", "username", "alex"),
        { key: "password", label: "password", value: null, secret: { itemId: it.id, field: SecretField.Password }, mono: true },
        field("checkbox", "Рабочий", "true"),
        field("link:101", "Тот же пароль", "→ Password"),
        field("link:none", "Пусто", null),
        field(null, "Своё поле", "значение"),
      ],
      notes: null,
      passkeys: [],
      passwordHistory: [],
    };
    for (const l of LANGS) {
      setLang(l);
      const d = new Directory(catalog);
      expect(() => buildDoc({ dir: d, detail, server: "s", places: [] }, `item:${it.id}`)).not.toThrow();
    }
  });
});

describe("every built-in field key the daemon can send has words", () => {
  it("is known to the window", () => {
    // Read from the daemon's own source, so a key added there without words
    // here fails this test instead of a person's window.
    const src = readFileSync(new URL("../../../../crates/vault/src/read.rs", import.meta.url), "utf8");
    const start = src.indexOf("pub fn detail(");
    expect(start).toBeGreaterThan(0);
    const body = src.slice(start, src.indexOf("\n}\n", start));
    const keys = new Set<string>();
    for (const m of body.matchAll(/(?:key: Some\("|(?:secret|visible)\(\s*")([a-zA-Z]+)"/g)) keys.add(m[1]!);
    for (const m of body.matchAll(/^\s+"([a-z][a-zA-Z]+)",$/gm)) keys.add(m[1]!);
    expect(keys.size).toBeGreaterThan(8);
    for (const key of keys) {
      if (key === "note") continue; // the note is not a field row: the backend lifts it out
      const f = field(key, key, key === "checkbox" ? "true" : "v");
      const label: Text = fieldLabel(f);
      for (const l of LANGS) {
        setLang(l);
        expect(() => text(label), `field "${key}" in ${l}`).not.toThrow();
      }
    }
  });
});

describe("an organisation's findings", () => {
  it("name who sees a critical item only when the members are known", async () => {
    const { orgFindings } = await import("./findings");
    setLang(Lang.Ru);
    const sub = (catalog: typeof DEMO) => {
      const f = orgFindings(new Directory(catalog), "org:acme").find((x) => "key" in x.sub && (x.sub.key === "find.itemSeen" || x.sub.key === "find.itemIn"));
      if (!f) throw new Error("no critical-item finding in the demo");
      return text(f.sub);
    };
    expect(sub(DEMO)).toMatch(/видят \d+/);
    expect(sub({ ...DEMO, membersLoading: true })).not.toMatch(/видят/);
  });
});
