// @vitest-environment happy-dom
// A page's buttons all do something: none is drawn and answered by nothing,
// a small action (a copy) is done at once rather than through a preview, a
// button that cannot work here (a site the item has none of) stands disabled
// and says why, and "More" holds the node's other verbs.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { App } from "../ui/App";
import { DemoBackend, DEMO_PLACES, demoContributions } from "../demo-backend";
import { DEMO } from "../demo";
import { Lang, setLang } from "../i18n";
import { Directory, NodeKind } from "../path/directory";
import { SettingsPage } from "../settings/pages";
import { buildDoc } from "./build";
import type { Action, Act } from "./spec";
import { CORE_VERBS } from "../verbs/core";
import { PreviewKind } from "../verbs/spec";

vi.mock("../ui/tokens", () => ({ tokenPx: () => 320 }));
(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const caught: unknown[] = [];
(globalThis as unknown as { reportError: (e: unknown) => void }).reportError = (e) => void caught.push(e);
const flush = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

const PAGES = [SettingsPage.Account, SettingsPage.Security, SettingsPage.Unlock, SettingsPage.Browsers, SettingsPage.App];

describe("a page's buttons", () => {
  const dir = new Directory(DEMO, demoContributions(), { places: DEMO_PLACES, settings: PAGES });
  const docs = dir
    .all()
    .filter((n) => n.kind !== NodeKind.Plugin || n.doc)
    .map((n) => ({ id: n.id, doc: buildDoc({ dir, detail: null, server: "vault.demo.example", places: DEMO_PLACES }, n.id) }));
  const actions = (d: (typeof docs)[number]["doc"]): Action[] => [...(d.hero.primary ? [d.hero.primary] : []), ...(d.hero.more ?? [])];

  it("are none of them answered by nothing", () => {
    const dead = docs.flatMap(({ id, doc }) => actions(doc).filter((a) => "none" in a.act && !a.off).map((a) => `${id}: ${JSON.stringify(a.label)}`));
    expect(dead).toEqual([]);
  });

  it("copy an item's secrets at once, without a preview", () => {
    const login = docs.find((d) => d.id === "item:aws")!.doc;
    const copies = actions(login).filter((a): a is Action & { act: Extract<Act, { copy: unknown }> } => "copy" in a.act);
    expect(copies.map((a) => a.act.copy.field)).toEqual(["password", "username", "totp"]);
    expect(actions(login).some((a) => "verb" in a.act && a.act.verb.startsWith("copy"))).toBe(false);
  });

  it("stand disabled, saying why, where the item has no site", () => {
    const bare = { ...DEMO, items: DEMO.items.map((i) => (i.id === "aws" ? { ...i, uris: [] } : i)) };
    const d = new Directory(bare, [], { settings: PAGES });
    const site = actions(buildDoc({ dir: d, detail: null, server: "s", places: [] }, "item:aws")).find((a) => a.icon === "ext")!;
    expect(site.off).toBeDefined();
    const withSite = actions(docs.find((x) => x.id === "item:aws")!.doc).find((a) => a.icon === "ext")!;
    expect(withSite.act).toEqual({ open: "https://console.aws.amazon.com" });
  });
});

describe("More", () => {
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

  it("lists the node's other verbs and opens the one picked on the line", async () => {
    const b = new DemoBackend();
    const lines: string[] = [];
    act(() => root.render(<App backend={b} line="personal › work › aws-production" onLine={(l) => lines.push(l)} autoBiometric={false} />));
    await flush();
    await flush();
    const more = host.querySelector<HTMLButtonElement>('.kw-hero button[aria-label="Ещё"]');
    expect(more).not.toBeNull();
    await act(async () => more!.click());
    const items = [...host.querySelectorAll<HTMLButtonElement>('.kw-more-menu [role="menuitem"]')];
    expect(items.length).toBeGreaterThan(0);
    const trash = items.find((x) => x.textContent?.includes("корзину") || x.textContent?.includes("Удалить"));
    await act(async () => (trash ?? items[0]!).click());
    await flush();
    await flush();
    expect(lines.at(-1)).toMatch(/ > /);
    expect(host.querySelector(".kw-more-menu")).toBeNull();
  });

  it("copies a password from the page at once", async () => {
    const b = new DemoBackend();
    act(() => root.render(<App backend={b} line="personal › work › aws-production" autoBiometric={false} />));
    await flush();
    await flush();
    const copy = [...host.querySelectorAll<HTMLButtonElement>(".kw-hero button")].find((x) => x.textContent?.includes("Копировать пароль"));
    await act(async () => copy!.click());
    await flush();
    expect(b.lastCopied).not.toBeNull();
    expect(host.querySelector("button[data-confirm]")).toBeNull();
  });
});

describe("a verb's preview", () => {
  it("changes a password for real: a new one made, copied and the site opened", () => {
    const dir = new Directory(DEMO, []);
    const p = CORE_VERBS.find((v) => v.id === "rotate")!.preview!(dir, "item:aws", "");
    expect(p.kind === PreviewKind.Ready && p.effect).toEqual({ rotate: { itemId: "aws", site: "https://console.aws.amazon.com" } });
  });

  it("offers no verb whose preview runs nothing", () => {
    const dir = new Directory(DEMO, []);
    const empty = CORE_VERBS.filter((v) => v.preview).flatMap((v) => {
      const at = v.example?.(dir) ?? null;
      if (!at || !v.applies(dir.node(at))) return [];
      const p = v.preview!(dir, at, "");
      return p.kind === PreviewKind.Ready && "none" in p.effect && !p.blocked ? [v.id] : [];
    });
    expect(empty).toEqual([]);
  });
});
