// The daemon's refusals arrive as dictionary keys, sometimes with values for
// their blanks: the window says them in words, and a message that is no key
// as it came.
import { afterEach, describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { isKey, Lang, setLang } from "../i18n";
import { faultWords } from "./fault";
import ruDaemon from "../i18n/daemon.ru.json";
import enDaemon from "../i18n/daemon.en.json";

describe("a refusal's words", () => {
  afterEach(() => setLang(Lang.Ru));

  it("says a daemon's key in the window's language", () => {
    setLang(Lang.Ru);
    expect(faultWords(new Error("err.badPin"))).toBe(ruDaemon["err.badPin"]);
    setLang(Lang.En);
    expect(faultWords(new Error("err.badPin"))).toBe(enDaemon["err.badPin"]);
  });

  it("fills a key's blanks with the values it came with", () => {
    setLang(Lang.En);
    const words = faultWords(new Error('err.extensionNotPaired {"words":"amber canyon"}'));
    expect(words).toContain("amber canyon");
    expect(words).not.toContain("err.");
  });

  it("shows a message that is no key as it came", () => {
    expect(faultWords(new Error("the daemon is away"))).toBe("the daemon is away");
  });

  it("knows every key the daemon's dictionary has, in both languages", () => {
    expect(Object.keys(ruDaemon).sort()).toEqual(Object.keys(enDaemon).sort());
  });

  it("knows every refusal the daemon can raise (the app's i18n/)", () => {
    for (const lang of ["ru", "en"]) {
      const root = JSON.parse(readFileSync(fileURLToPath(new URL(`../../../../i18n/${lang}.json`, import.meta.url)), "utf8")) as Record<string, unknown>;
      const missing = Object.keys(root).filter((k) => (k.startsWith("err.") || k.startsWith("touch.")) && !isKey(k));
      expect(missing).toEqual([]);
    }
  });
});
