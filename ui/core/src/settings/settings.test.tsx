// @vitest-environment happy-dom
// The settings: every row's words in both languages, exactly one choice in
// force (even a value set by hand that no choice names), the pages on the
// path under Settings and nowhere else, the theme and language carried out,
// and a switch on a page that saves through the backend and shows what the
// backend answered — or stays as it was when the backend refuses.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App } from "../ui/App";
import { DemoBackend, DEMO_SETTINGS } from "../demo-backend";
import { DEMO } from "../demo";
import { allTexts, Lang, setLang, currentLang } from "../i18n";
import { Directory, NodeKind } from "../path/directory";
import { ROWS, RowKind, SettingKey } from "./rows";
import { pageDoc, pageId, SETTINGS_ID, SettingsPage } from "./pages";
import { applyLook, langOf } from "./apply";
import { LanguageChoice, LockTimeoutKind, ThemeChoice } from "./types";

// The window measures its layout tokens from the CSS, which this page has
// none of: they are given their sizes.
vi.mock("../ui/tokens", () => ({ tokenPx: () => 320 }));

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
// A render that fails is reported to the page; here it fails the test, with its message.
const caught: unknown[] = [];
(globalThis as unknown as { reportError: (e: unknown) => void }).reportError = (e) => void caught.push(e);
const flush = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

describe("the settings' rows", () => {
  it("have their words in both languages", () => {
    for (const key of Object.values(SettingKey)) {
      const row = ROWS[key];
      expect(allTexts(row.title).every((w) => w.length > 0)).toBe(true);
      if (row.hint) expect(allTexts(row.hint(DEMO_SETTINGS)).every((w) => w.length > 0)).toBe(true);
    }
  });

  it("show exactly one choice in force", () => {
    for (const key of Object.values(SettingKey)) {
      const row = ROWS[key];
      if (row.kind === RowKind.Choice) expect(row.choices(DEMO_SETTINGS).filter((c) => c.on)).toHaveLength(1);
    }
  });

  it("keep a value set by hand among the choices, chosen", () => {
    const s = { ...DEMO_SETTINGS, clipboardClearSeconds: 45, lockTimeout: { kind: LockTimeoutKind.Minutes as const, minutes: 7 } };
    const clip = ROWS[SettingKey.Clipboard];
    const lock = ROWS[SettingKey.LockTimeout];
    if (clip.kind !== RowKind.Choice || lock.kind !== RowKind.Choice) throw new Error("not choices");
    expect(clip.choices(s).filter((c) => c.on).map((c) => c.patch)).toEqual([{ clipboardClearSeconds: 45 }]);
    expect(lock.choices(s).filter((c) => c.on).map((c) => c.patch)).toEqual([{ lockTimeout: { kind: LockTimeoutKind.Minutes, minutes: 7 } }]);
  });

  it("change only their own setting", () => {
    const t = ROWS[SettingKey.HideOnCopy];
    if (t.kind !== RowKind.Toggle) throw new Error("not a switch");
    expect(t.patch(true)).toEqual({ hideOnCopy: true });
  });
});

describe("the settings on the path", () => {
  const pages = [SettingsPage.Security, SettingsPage.Unlock, SettingsPage.App];

  it("stand under Settings, after the vault's things, with a page each", () => {
    const dir = new Directory(DEMO, [], { settings: pages });
    expect(dir.kidIds("root").at(-1)).toBe(SETTINGS_ID);
    expect(dir.kidIds(SETTINGS_ID)).toEqual(pages.map(pageId));
    for (const p of pages) expect(dir.node(pageId(p)).kind).toBe(NodeKind.SettingsPage);
  });

  it("are not there for an app that keeps none", () => {
    const dir = new Directory(DEMO, []);
    expect(dir.has(SETTINGS_ID)).toBe(false);
    expect(dir.kidIds("root")).not.toContain(SETTINGS_ID);
  });

  it("keep their slugs when an item is named Settings", () => {
    const named = { ...DEMO, items: [...DEMO.items, { ...DEMO.items[0]!, id: "settings-item", name: "Settings" }] };
    const dir = new Directory(named, [], { settings: pages });
    expect(dir.node(SETTINGS_ID).slug).toBe("settings");
    expect(dir.node("item:settings-item").slug).not.toBe("settings");
  });

  it("are found by none of the vault's searches", () => {
    const dir = new Directory(DEMO, [], { settings: pages });
    expect(dir.universe("root")).not.toContain(SETTINGS_ID);
  });

  it("each draw their rows from the known settings", () => {
    for (const p of pages) {
      const keys = pageDoc(p).sections.flatMap((s) => s.blocks.map((b) => ("setting" in b ? b.setting : null)));
      expect(keys.every((k) => k !== null && k in ROWS)).toBe(true);
    }
  });
});

describe("the look", () => {
  afterEach(() => setLang(Lang.Ru));

  it("follows the system's language for auto", () => {
    expect(langOf(LanguageChoice.Auto, "ru-RU")).toBe(Lang.Ru);
    expect(langOf(LanguageChoice.Auto, "de-DE")).toBe(Lang.En);
    expect(langOf(LanguageChoice.En, "ru-RU")).toBe(Lang.En);
  });

  it("sets the theme and drops it for the system's", () => {
    const root = document.createElement("html");
    applyLook({ ...DEMO_SETTINGS, theme: ThemeChoice.Dark, language: LanguageChoice.En }, root, "ru");
    expect(root.dataset.theme).toBe("dark");
    expect(currentLang()).toBe(Lang.En);
    applyLook({ ...DEMO_SETTINGS, theme: ThemeChoice.System }, root, "ru");
    expect(root.dataset.theme).toBeUndefined();
  });
});

describe("a settings page", () => {
  let host: HTMLDivElement;
  let root: Root;
  beforeEach(() => {
    setLang(Lang.Ru);
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
  });
  afterEach(() => {
    expect(caught.map(String)).toEqual([]);
    act(() => root.unmount());
    host.remove();
    setLang(Lang.Ru);
    delete document.documentElement.dataset.theme;
  });

  const switchOf = (words: string) => [...host.querySelectorAll<HTMLButtonElement>('[role="switch"]')].find((b) => b.getAttribute("aria-label") === words);

  it("saves a switch through the backend and shows what it answered", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} line="settings › settings-app" autoBiometric={false} />));
    await flush();
    await flush();
    const sw = switchOf("Сворачивать при копировании");
    expect(sw?.getAttribute("aria-checked")).toBe("false");
    await act(async () => sw!.click());
    await flush();
    expect((await b.settings()).hideOnCopy).toBe(true);
    expect(switchOf("Сворачивать при копировании")?.getAttribute("aria-checked")).toBe("true");
  });

  it("stays as it was when the backend refuses, and says why", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} line="settings › settings-app" autoBiometric={false} />));
    await flush();
    await flush();
    b.failNext = "the daemon is away";
    await act(async () => switchOf("Сворачивать при копировании")!.click());
    await flush();
    expect((await b.settings()).hideOnCopy).toBe(false);
    expect(switchOf("Сворачивать при копировании")?.getAttribute("aria-checked")).toBe("false");
    expect(document.body.textContent).toContain("Настройка не сохранилась: the daemon is away");
  });
});
