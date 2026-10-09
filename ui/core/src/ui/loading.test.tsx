// @vitest-environment happy-dom
// What stands while something is on its way: the boot screen's words in each
// phase and language, the app never showing an empty window while its
// session or catalogue is on its way, the cross-fade out of the boot screen,
// the failure sheet's way on, and the documents' skeletons (an item's fields
// while it is read, the members table while the members are).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { renderToString } from "react-dom/server";
import { App } from "./App";
import { LoadPhase, Loading, phaseWords, BlockSkeleton } from "./Loading";
import { DemoBackend, DEMO_PLACES, demoContributions } from "../demo-backend";
import { DEMO, DEMO_NOW } from "../demo";
import { setLang, Lang, text } from "../i18n";
import { type Session, SessionState, ChangeKind } from "../backend";
import type { Catalog } from "../model/types";
import type { Contribution } from "../path/directory";
import { Directory } from "../path/directory";
import { DEFAULT_PLACES } from "../path/places";
import { buildDoc } from "../doc/build";
import { SkeletonKind } from "../doc/spec";

(globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const deferred = <T,>() => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

/// A demo backend whose session, catalogue and places answer only when the
/// test says so.
function heldBackend() {
  const b = new DemoBackend();
  const session = deferred<Session>();
  const catalog = deferred<Catalog>();
  const places = deferred<Contribution[]>();
  b.session = () => session.promise;
  b.catalog = () => catalog.promise;
  b.contributions = () => places.promise;
  return { b, session, catalog, places };
}

const flush = () => act(async () => {
  await new Promise((r) => setTimeout(r, 0));
});

describe("the boot screen", () => {
  beforeEach(() => setLang(Lang.Ru));
  afterEach(() => setLang(Lang.Ru));

  it("says each phase in Russian and in English", () => {
    const ru = [phaseWords(LoadPhase.Session), phaseWords(LoadPhase.Catalog), phaseWords(LoadPhase.Places)];
    expect(ru).toEqual(["Открываю хранилище…", "Читаю записи…", "Загружаю места плагинов…"]);
    setLang(Lang.En);
    expect([phaseWords(LoadPhase.Session), phaseWords(LoadPhase.Catalog), phaseWords(LoadPhase.Places)]).toEqual(["Opening the vault…", "Reading the items…", "Loading the plugins' places…"]);
  });

  it("is the window's skeleton with its phase's words and a running bar", () => {
    for (const p of Object.values(LoadPhase)) {
      const html = renderToString(<Loading phase={p} />);
      expect(html).toContain("loading");
      expect(html).toContain("strip");
      expect(html).toContain("load-bar");
      expect(html).toContain("load-crumb-mark");
      expect(html).toContain(phaseWords(p));
      expect(html).not.toContain("leaving");
      // two list columns of two-line rows, then the inspector's hero
      expect(html.match(/sk-col/g)?.length).toBe(2);
      expect(html.match(/sk-row/g)?.length).toBe(14);
      expect(html).toContain("sk-hero-tile");
    }
    expect(renderToString(<Loading phase={LoadPhase.Session} leaving />)).toContain("leaving");
  });

  it("is what the app draws first, never an empty window", () => {
    const { b } = heldBackend();
    const html = renderToString(<App backend={b} />);
    expect(html).toContain("loading");
    expect(html).toContain("Открываю хранилище…");
    expect(html).not.toMatch(/<div class="window"><\/div>/);
  });
});

describe("the app while it loads", () => {
  let host: HTMLDivElement;
  let root: Root;
  beforeEach(() => {
    setLang(Lang.Ru);
    host = document.createElement("div");
    document.body.appendChild(host);
    root = createRoot(host);
  });
  afterEach(() => {
    act(() => root.unmount());
    host.remove();
  });

  const loading = () => host.querySelector(".loading");
  const words = () => host.querySelector(".loading .load-words")?.textContent;
  const noEmptyWindow = () => {
    for (const w of host.querySelectorAll(".window")) expect(w.childElementCount).toBeGreaterThan(0);
  };

  it("shows the boot screen until the session, then the catalogue, then the places come", async () => {
    const h = heldBackend();
    act(() => root.render(<App backend={h.b} autoBiometric={false} />));
    expect(loading()).not.toBeNull();
    expect(words()).toBe("Открываю хранилище…");
    noEmptyWindow();

    h.session.resolve({ state: SessionState.Unlocked, email: "alex@acme.example", server: "s", name: "Alex" });
    await flush();
    expect(words()).toBe("Читаю записи…");
    noEmptyWindow();

    h.catalog.resolve(structuredClone(DEMO));
    await flush();
    expect(words()).toBe("Загружаю места плагинов…");
    expect(loading()!.classList.contains("leaving")).toBe(false);
    noEmptyWindow();
  });

  it("fades out over the gate when the session is closed, then is gone", async () => {
    const h = heldBackend();
    act(() => root.render(<App backend={h.b} autoBiometric={false} />));
    h.session.resolve({ state: SessionState.Locked, email: "alex@acme.example", server: "s" });
    await flush();
    // The gate stands, and the boot screen fades out over it, out of reach.
    expect(host.querySelector(".gate")).not.toBeNull();
    const veil = loading()!;
    expect(veil.classList.contains("leaving")).toBe(true);
    expect(veil.hasAttribute("inert")).toBe(true);
    act(() => {
      veil.dispatchEvent(new Event("animationend", { bubbles: true }));
    });
    expect(loading()).toBeNull();
  });

  it("says a load that failed calmly, with a way to try again", async () => {
    const h = heldBackend();
    act(() => root.render(<App backend={h.b} autoBiometric={false} />));
    h.session.reject(new Error("the daemon is not running"));
    await flush();
    const sheet = host.querySelector(".load-failed")!;
    expect(sheet).not.toBeNull();
    expect(sheet.textContent).toContain("Хранилище не открылось");
    expect(sheet.textContent).toContain("the daemon is not running");
    // Trying again brings the boot screen back while the session is asked again.
    const again = heldBackend();
    h.b.session = () => again.session.promise;
    const button = sheet.querySelector("button")!;
    expect(button.textContent).toBe("Повторить");
    act(() => button.click());
    expect(host.querySelector(".load-failed")).toBeNull();
    expect(words()).toBe("Открываю хранилище…");
  });
});

describe("skeletons in documents", () => {
  const places = [...DEFAULT_PLACES, ...DEMO_PLACES];
  const dirOf = (c: Catalog) => new Directory(c, demoContributions(), { now: DEMO_NOW, places });

  it("stand for an item's fields while the item is read", () => {
    const doc = buildDoc({ dir: dirOf(DEMO), detail: null, server: "s", places }, "item:aws");
    // The hero is known from the node; the fields are on their way.
    expect(text(doc.hero.title)).toBe("AWS — production");
    const blocks = doc.sections.flatMap((s) => s.blocks);
    expect(blocks.some((b) => "skeleton" in b && b.skeleton === SkeletonKind.Fields && b.rows > 0)).toBe(true);
    expect(blocks.some((b) => "secret" in b)).toBe(false);
  });

  it("stand for the members table while the members are read, with its words", () => {
    setLang(Lang.Ru);
    const coming: Catalog = { ...structuredClone(DEMO), members: [], membersLoading: true };
    const doc = buildDoc({ dir: dirOf(coming), detail: null, server: "s", places }, "org:acme");
    const sk = doc.sections.flatMap((s) => s.blocks).find((b) => "skeleton" in b);
    expect(sk && "skeleton" in sk && sk.skeleton).toBe(SkeletonKind.Members);
    expect(sk && "words" in sk && sk.words && text(sk.words)).toBe("Загружаю участников…");
    expect(doc.note).toBeUndefined();
    const html = renderToString(<BlockSkeleton kind={SkeletonKind.Members} rows={4} words={{ key: "load.members" }} />);
    expect(html.match(/sk-mt/g)?.length).toBe(4);
    expect(html).toContain("Загружаю участников…");
    expect(html).toContain("sk-late");
  });

  it("are not drawn where the members are not on their way", () => {
    // No members, and none coming: the admins-only note, as before.
    const none: Catalog = { ...structuredClone(DEMO), members: [] };
    const doc = buildDoc({ dir: dirOf(none), detail: null, server: "s", places }, "org:acme");
    expect(doc.sections.flatMap((s) => s.blocks).some((b) => "skeleton" in b)).toBe(false);
    expect(doc.note).toBeDefined();
    // An organisation that cannot manage members shows none coming either.
    const coming: Catalog = { ...structuredClone(DEMO), members: [], membersLoading: true };
    const globex = buildDoc({ dir: dirOf(coming), detail: null, server: "s", places }, "org:globex");
    expect(globex.sections.flatMap((s) => s.blocks).some((b) => "skeleton" in b)).toBe(false);
  });
});

describe("the demo, slowed", () => {
  it("answers its reads late and brings the members in a change of their own", async () => {
    const b = new DemoBackend({ slow: 20 });
    const changes: ChangeKind[] = [];
    b.subscribe((c) => changes.push(c.kind));
    const t0 = Date.now();
    const first = await b.catalog();
    expect(Date.now() - t0).toBeGreaterThanOrEqual(15);
    expect(first.membersLoading).toBe(true);
    expect(first.members).toEqual([]);
    await new Promise((r) => setTimeout(r, 60));
    expect(changes).toContain(ChangeKind.Catalog);
    const then = await b.catalog();
    expect(then.membersLoading).toBeUndefined();
    expect(then.members.length).toBeGreaterThan(0);
    expect(() => new DemoBackend({ slow: -1 })).toThrow();
  });
});
