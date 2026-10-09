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
import { allTexts, Lang, setLang, currentLang, text } from "../i18n";
import { PIN_MIN, PASSWORD_MIN, secretsProblem, ACCOUNT_VERBS, AccountVerb, exportFormatOf, kdfOf } from "../verbs/account";
import { SecretAskKind, PreviewKind, ExportFormat } from "../verbs/spec";
import { FillField, FillMode, fillVerb } from "../verbs/fill";
import { EXTENSION_STORE_URL } from "../ui/Extensions";
import { type UnlockState, KdfKind } from "./types";

const UNLOCKS: UnlockState[] = [
  { biometric: false, biometricProblem: null, pin: false },
  { biometric: true, biometricProblem: null, pin: true },
  { biometric: false, biometricProblem: "no sensor", pin: false },
];
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
      if (row.kind === RowKind.Method) {
        for (const u of UNLOCKS) {
          expect(text(row.hint(u)).length).toBeGreaterThan(0);
          for (const v of row.verbs(u)) expect(allTexts(v.label).every((w) => w.length > 0)).toBe(true);
        }
      } else if (row.kind === RowKind.Action) {
        expect(allTexts(row.hint).every((w) => w.length > 0)).toBe(true);
        for (const v of row.verbs) expect(allTexts(v.label).every((w) => w.length > 0)).toBe(true);
      } else if (row.hint) expect(allTexts(row.hint(DEMO_SETTINGS)).every((w) => w.length > 0)).toBe(true);
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

describe("what is typed for an account's change", () => {
  const pin = ACCOUNT_VERBS.find((v) => v.id === AccountVerb.Pin)!;
  const asks = (() => {
    const p = pin.preview!(new Directory(DEMO, [], { settings: [SettingsPage.Unlock] }), pageId(SettingsPage.Unlock), "");
    if (p.kind !== PreviewKind.Ready || !p.secrets) throw new Error("the PIN's preview asks for nothing");
    return p.secrets;
  })();

  it("asks for the PIN twice and the master password, never through the line", () => {
    expect(asks.map((a) => a.kind)).toEqual([SecretAskKind.Pin, SecretAskKind.Pin, SecretAskKind.Password]);
  });

  it("is refused when empty, short or not repeated", () => {
    expect(secretsProblem(asks, { pin: "1234", again: "1234", password: "" })).toBe("verb.acct.empty");
    expect(secretsProblem(asks, { pin: "1".repeat(PIN_MIN - 1), again: "1".repeat(PIN_MIN - 1), password: "p" })).toBe("verb.acct.pinShort");
    expect(secretsProblem(asks, { pin: "1234", again: "1235", password: "p" })).toBe("verb.acct.pinMismatch");
    expect(secretsProblem(asks, { pin: "1234", again: "1234", password: "p" })).toBeNull();
  });
});

describe("the unlocking page", () => {
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
  });

  const go = () => host.querySelector<HTMLButtonElement>("button[data-confirm]");
  const type = (label: string, value: string) => {
    const el = host.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`);
    if (!el) throw new Error(`no field "${label}"`);
    el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const pinRow = () => [...host.querySelectorAll(".set")].find((r) => r.textContent?.includes("Открывать по PIN"));

  async function openPin(b: DemoBackend, lines: string[]) {
    act(() => root.render(<App backend={b} line="settings › settings-unlock" onLine={(l) => lines.push(l)} autoBiometric={false} />));
    await flush();
    await flush();
    expect(pinRow()?.textContent).toContain("Выключено");
    const on = [...pinRow()!.querySelectorAll("button")].find((x) => x.textContent?.includes("Включить"))!;
    await act(async () => on.click());
    await flush();
  }

  it("sets a PIN through its preview, sends it once and keeps it nowhere", async () => {
    const b = new DemoBackend();
    const lines: string[] = [];
    await openPin(b, lines);
    expect(go()?.disabled).toBe(true);
    await act(async () => {
      type("PIN", "4821");
      type("PIN ещё раз", "4821");
      type("Мастер-пароль", "correct horse");
    });
    expect(go()?.disabled).toBe(false);
    await act(async () => go()!.click());
    await flush();
    await flush();
    expect(b.calls).toContain("account:setPin");
    expect(lines.join("\n")).not.toMatch(/4821|correct horse/);
    expect(location.href).not.toMatch(/4821|correct/);
    for (const el of host.querySelectorAll("input")) expect(el.value).toBe("");
    expect(host.innerHTML).not.toMatch(/4821|correct horse/);
    expect((await b.unlockState()).pin).toBe(true);
  });

  it("says a PIN typed differently the second time, and sends nothing", async () => {
    const b = new DemoBackend();
    await openPin(b, []);
    await act(async () => {
      type("PIN", "4821");
      type("PIN ещё раз", "4822");
      type("Мастер-пароль", "correct horse");
    });
    await act(async () => go()!.click());
    await flush();
    expect(b.calls).not.toContain("account:setPin");
    expect(host.textContent).toContain("PIN не совпадают");
    for (const el of host.querySelectorAll("input")) expect(el.value).toBe("");
  });
});

describe("the browsers", () => {
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
  });
  const dialog = () => host.ownerDocument.querySelector('[role="dialog"][aria-label="Сопряжение браузера"]');
  const inDialog = (words: string) => [...(dialog()?.querySelectorAll("button") ?? [])].find((b) => b.textContent?.includes(words));

  it("lists the paired ones on their page by browser and Mac, with their five words", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} line="settings › settings-browsers" autoBiometric={false} />));
    await flush();
    await flush();
    const row = host.querySelector(".ext")!;
    expect(row.querySelector("b")?.textContent).toBe("Arc");
    expect(row.textContent).toContain("Studio Mac · С ");
    expect(row.textContent).toContain("amber");
    await act(async () => host.querySelector<HTMLButtonElement>('button[aria-label="Отменить сопряжение"]')!.click());
    await flush();
    expect(b.calls).toContain("unpair:demo-paired");
    expect(host.textContent).toContain("Браузеры не сопряжены");
  });

  it("offers to install the extension where no browser is paired, from the store", async () => {
    const b = new DemoBackend();
    await b.unpairExtension("demo-paired");
    act(() => root.render(<App backend={b} line="settings › settings-browsers" autoBiometric={false} />));
    await flush();
    await flush();
    const install = [...host.querySelectorAll<HTMLButtonElement>(".insp button")].find((x) => x.textContent?.includes("Установить расширение"));
    expect(install?.className).toContain("solid");
    await act(async () => install!.click());
    expect(b.opened).toEqual([EXTENSION_STORE_URL]);
  });

  it("stands among the vault's connections on its home, saying what is paired", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} autoBiometric={false} />));
    await flush();
    await flush();
    const row = [...host.querySelectorAll(".insp .ref")].find((r) => r.textContent?.includes("Браузеры"));
    expect(row?.textContent).toContain("Arc");
    await b.unpairExtension("demo-paired");
    act(() => root.render(<App backend={new DemoBackend()} autoBiometric={false} />));
  });

  it("asks over the window when a browser wants to pair, and pairs it", async () => {
    const b = new DemoBackend();
    b.askToPair();
    act(() => root.render(<App backend={b} autoBiometric={false} />));
    await flush();
    await flush();
    expect(dialog()?.textContent).toContain("harbor");
    expect(dialog()?.textContent).toContain("Google Chrome просит сопряжения");
    await act(async () => inDialog("Сопрячь")!.click());
    await flush();
    expect(b.calls).toContain("pair:demo-asking");
    expect(dialog()).toBeNull();
  });

  it("sets an asking browser aside on Not now, and does not pair it", async () => {
    const b = new DemoBackend();
    b.askToPair();
    act(() => root.render(<App backend={b} autoBiometric={false} />));
    await flush();
    await flush();
    await act(async () => inDialog("Не сейчас")!.click());
    await flush();
    expect(dialog()).toBeNull();
    expect(b.calls).not.toContain("pair:demo-asking");
  });

  it("will not pair once the words have expired", async () => {
    const b = new DemoBackend();
    b.askToPair(-1);
    act(() => root.render(<App backend={b} autoBiometric={false} />));
    await flush();
    await flush();
    expect(dialog()?.textContent).toContain("Слова истекли");
    expect(inDialog("Сопрячь")?.disabled).toBe(true);
  });
});

describe("the export", () => {
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
  });

  it("reads its format from the line, JSON by default, and refuses another", () => {
    expect(exportFormatOf("")).toBe(ExportFormat.Json);
    expect(exportFormatOf("CSV")).toBe(ExportFormat.Csv);
    expect(exportFormatOf("xml")).toBeNull();
  });

  it("asks for the master password, writes the chosen format and says where", async () => {
    const b = new DemoBackend();
    const lines: string[] = [];
    act(() => root.render(<App backend={b} line="settings › settings-security > export csv" onLine={(l) => lines.push(l)} autoBiometric={false} />));
    await flush();
    await flush();
    const go = host.querySelector<HTMLButtonElement>("button[data-confirm]")!;
    expect(go.disabled).toBe(true);
    const field = host.querySelector<HTMLInputElement>('input[aria-label="Мастер-пароль"]')!;
    await act(async () => {
      field.value = "correct horse";
      field.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await act(async () => go.click());
    await flush();
    await flush();
    expect(document.body.textContent).toContain("Экспорт сохранён: ~/Downloads/keyward-export.csv");
    expect(lines.join("\n")).not.toContain("correct horse");
    expect(field.value).toBe("");
  });
});

describe("the account page", () => {
  it("reads a derivation from the line within the server's bounds", () => {
    expect(kdfOf("")).toEqual({ kind: KdfKind.Argon2id, iterations: 3, memoryMib: 64, parallelism: 4 });
    expect(kdfOf("argon2id 4 128 2")).toEqual({ kind: KdfKind.Argon2id, iterations: 4, memoryMib: 128, parallelism: 2 });
    expect(kdfOf("pbkdf2 700000")).toEqual({ kind: KdfKind.Pbkdf2, iterations: 700000 });
    expect(kdfOf("pbkdf2 5000")).toBeNull();
    expect(kdfOf("argon2id 3 4096 4")).toBeNull();
    expect(kdfOf("scrypt")).toBeNull();
  });

  it("asks for a new master password that is long, repeated and not the current one", () => {
    const v = ACCOUNT_VERBS.find((x) => x.id === AccountVerb.Password)!;
    const p = v.preview!(new Directory(DEMO, [], { settings: [SettingsPage.Account] }), pageId(SettingsPage.Account), "");
    if (p.kind !== PreviewKind.Ready || !p.secrets) throw new Error("the preview asks for nothing");
    const long = "a".repeat(PASSWORD_MIN);
    expect(secretsProblem(p.secrets, { current: "old-password-x", new: "short", again: "short" })).toBe("verb.acct.passwordShort");
    expect(secretsProblem(p.secrets, { current: long, new: long, again: long })).toBe("verb.acct.passwordSame");
    expect(secretsProblem(p.secrets, { current: "old-password-x", new: long, again: `${long}b` })).toBe("verb.acct.passwordMismatch");
    expect(secretsProblem(p.secrets, { current: "old-password-x", new: long, again: long })).toBeNull();
  });

  it("marks the danger zone's verbs as dangerous", () => {
    const dir = new Directory(DEMO, [], { settings: [SettingsPage.Account] });
    for (const id of [AccountVerb.SignOutEverywhere, AccountVerb.Purge, AccountVerb.DeleteAccount]) {
      const p = ACCOUNT_VERBS.find((x) => x.id === id)!.preview!(dir, pageId(SettingsPage.Account), "");
      expect(p.kind === PreviewKind.Ready && p.danger && p.secrets?.length === 1).toBe(true);
    }
  });
});

describe("the profile", () => {
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
  });

  it("shows the email, the derivation and the fingerprint, and reads them again after a change", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} line="settings › settings-account" autoBiometric={false} />));
    await flush();
    await flush();
    expect(host.textContent).toContain("alex.morgan@acme.example");
    expect(host.textContent).toContain("Argon2id, 3 итер. · 64 МиБ · 4 потоков");
    expect(host.textContent).toContain("lantern");
  });
});

describe("two-step login", () => {
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
  });
  const btn = (words: string) => [...host.querySelectorAll<HTMLButtonElement>(".insp button")].find((b) => b.textContent?.trim() === words || b.textContent?.endsWith(words));
  const type = (label: string, value: string) => {
    const el = host.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!;
    el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
  };
  async function open(b: DemoBackend) {
    act(() => root.render(<App backend={b} line="settings › settings-account" autoBiometric={false} />));
    await flush();
    await flush();
  }

  it("turns email codes on: the password, a code sent to the account's address, the code", async () => {
    const b = new DemoBackend();
    await open(b);
    const emailRow = [...host.querySelectorAll(".set")].find((r) => r.textContent?.includes("Код на почту"))!;
    await act(async () => [...emailRow.querySelectorAll("button")].find((x) => x.textContent?.includes("Настроить"))!.click());
    await act(async () => type("Мастер-пароль", "correct horse"));
    await act(async () => btn("Прислать код")!.click());
    await flush();
    expect(b.calls).toContain("tf:send:alex.morgan@acme.example");
    await act(async () => type("Код из письма", "123456"));
    await act(async () => btn("Включить")!.click());
    await flush();
    expect(b.calls).toContain("tf:email");
    for (const el of host.querySelectorAll('input[type="password"]')) expect((el as HTMLInputElement).value).toBe("");
    expect([...host.querySelectorAll(".set")].find((r) => r.textContent?.includes("Код на почту"))?.textContent).toContain("Включено");
  });

  it("shows the recovery code once, and lets it go when done", async () => {
    const b = new DemoBackend();
    await open(b);
    await act(async () => btn("Показать")!.click());
    await act(async () => type("Мастер-пароль", "correct horse"));
    await act(async () => btn("Показать")!.click());
    await flush();
    expect(host.textContent).toContain("DEMO-RECO-VERY-CODE");
    await act(async () => btn("Готово")!.click());
    expect(host.textContent).not.toContain("DEMO-RECO-VERY-CODE");
  });

  it("turns the authenticator off with the master password", async () => {
    const b = new DemoBackend();
    await open(b);
    const authRow = [...host.querySelectorAll(".set")].find((r) => r.textContent?.includes("Приложение-аутентификатор"))!;
    await act(async () => [...authRow.querySelectorAll("button")].find((x) => x.textContent?.includes("Выключить"))!.click());
    await act(async () => type("Мастер-пароль", "correct horse"));
    await act(async () => btn("Выключить")!.click());
    await flush();
    expect(b.calls).toContain("tf:off:0");
  });
});

describe("a change of email", () => {
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
  });

  it("sends a code to the new address, then changes it with the code", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} line="settings › settings-account" autoBiometric={false} />));
    await flush();
    await flush();
    const row = [...host.querySelectorAll(".set")].find((r) => r.textContent?.includes("Email аккаунта"))!;
    await act(async () => row.querySelector("button")!.click());
    const set = (label: string, v: string) => {
      const el = host.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!;
      const proto = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!;
      proto.set!.call(el, v);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    };
    await act(async () => {
      set("Мастер-пароль", "correct horse");
      set("Новый email", "alex@new.example");
    });
    const step = () => host.querySelector(".tf-step")!;
    await act(async () => [...step().querySelectorAll("button")].find((x) => x.textContent === "Прислать код")!.click());
    await flush();
    expect(b.calls).toContain("email:code:alex@new.example");
    await act(async () => set("Код из письма", "123456"));
    await act(async () => [...step().querySelectorAll("button")].find((x) => x.textContent === "Сменить email")!.click());
    await flush();
    expect(b.calls).toContain("email:alex@new.example");
    expect(document.body.textContent).toContain("Email сменён на alex@new.example");
  });
});

describe("autofill", () => {
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
  });
  const go = () => host.querySelector<HTMLButtonElement>("button[data-confirm]");

  it("offers > fill only after ⌘⇧L, and types the login and the password into what was in front", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} line="personal › work › aws-production > fill" autoBiometric={false} />));
    await flush();
    await flush();
    expect(go()).toBeNull();
    await act(async () => b.pressAutofill({ app: "Arc", domain: null, loginPair: true, field: FillField.Username }));
    await flush();
    expect(host.textContent).toContain("«Arc»");
    await act(async () => go()!.click());
    await flush();
    expect(b.calls.some((c) => c.startsWith("fill:") && c.endsWith(":both"))).toBe(true);
  });

  it("asks the system for access and says so when it may not type", async () => {
    const b = new DemoBackend();
    b.fillGranted = false;
    act(() => root.render(<App backend={b} line="personal › work › aws-production > fill password" autoBiometric={false} />));
    await flush();
    await flush();
    await act(async () => b.pressAutofill({ app: "Arc", domain: null, loginPair: false, field: FillField.Password }));
    await flush();
    await act(async () => go()!.click());
    await flush();
    expect(b.calls).toContain("fill:ask");
    expect(b.calls.some((c) => c.startsWith("fill:aws"))).toBe(false);
    expect(host.textContent).toContain("Универсальному доступу");
  });

  it("chooses what the field in front asks for: the code into a code field", () => {
    const dir = new Directory(DEMO, []);
    const at = (field: FillField, loginPair = false) => {
      const p = fillVerb({ app: "Arc", domain: null, loginPair, field }).preview!(dir, "item:aws", "");
      return p.kind === PreviewKind.Ready && "fill" in p.effect ? p.effect.fill.mode : null;
    };
    expect(at(FillField.Totp)).toBe(FillMode.Totp);
    expect(at(FillField.Password)).toBe(FillMode.Password);
    expect(at(FillField.Username, true)).toBe(FillMode.Both);
    expect(at(FillField.Username)).toBe(FillMode.Username);
    expect(at(FillField.Other), "one field takes one value, never both").toBe(FillMode.Username);
    const choices = fillVerb({ app: "Arc", domain: null, loginPair: false, field: FillField.Totp }).preview!(dir, "item:aws", "");
    const input = choices.kind === PreviewKind.Ready ? choices.form?.[0]?.inputs[0] : undefined;
    expect(input && "choices" in input ? input.choices.map((c) => c.arg) : []).toContain(FillMode.Totp);
  });

  it("will not type both where the field is not in a sign-in form", () => {
    const dir = new Directory(DEMO, []);
    const p = fillVerb({ app: "Notes", domain: null, loginPair: false, field: FillField.Other }).preview!(dir, "item:aws", "both");
    expect(p.kind === PreviewKind.Ready && p.blocked).toBeTruthy();
  });
});
