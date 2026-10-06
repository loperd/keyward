// What the window lets go of and what it refuses to show: places kept
// nowhere by default, nothing of the vault reachable after a lock, a slow
// reveal never landing in the wrong field, a re-prompt item never fetched
// without the password.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Backend, Revealed } from "../backend";
import { DEMO, DEMO_NOW } from "../demo";
import { DemoBackend } from "../demo-backend";
import { text, Lang } from "../i18n";
import { Directory } from "../path/directory";
import { loadPlaces, PLACE_KEY, placeFor, type PlaceStore } from "../path/places";
import { Query } from "../path/query";
import { CORE_VERBS } from "../verbs/core";
import { Reprompt } from "./reprompt";
import { isLockedError, RevealSession } from "./reveal-session";
import { SessionHold } from "./session-hold";

const icons = new Set(["server", "person", "filter", "search", "card", "login", "key"]);
const query = () => new Query(new Directory(DEMO, [], { now: DEMO_NOW }), CORE_VERBS);

describe("places are kept nowhere by default", () => {
  let storage: { getItem: ReturnType<typeof vi.fn>; setItem: ReturnType<typeof vi.fn> };
  beforeEach(() => {
    storage = { getItem: vi.fn(() => null), setItem: vi.fn() };
    vi.stubGlobal("localStorage", storage);
  });
  afterEach(() => vi.unstubAllGlobals());

  it("never touches the browser's storage and forgets them with the session", () => {
    const hold = new SessionHold(new DemoBackend());
    expect(hold.opened(DEMO, icons)?.places).toEqual([]);
    const q = query();
    const p = placeFor(q, q.compile("personal › work › aws-production"));
    expect(hold.savePlaces([p])).toBe(true);
    expect(hold.places.getItem(PLACE_KEY)).toContain(p.line);
    expect(storage.setItem).not.toHaveBeenCalled();
    expect(storage.getItem).not.toHaveBeenCalled();
    hold.close();
    expect(hold.places.getItem(PLACE_KEY)).toBeNull();
    expect(hold.opened(DEMO, icons)?.places).toEqual([]);
  });

  it("keeps them only in a store the app hands in, across sessions", () => {
    const m = new Map<string, string>();
    const store: PlaceStore = { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => void m.set(k, v) };
    const hold = new SessionHold(new DemoBackend(), store);
    hold.opened(DEMO, icons);
    const q = query();
    hold.savePlaces([placeFor(q, q.compile("acme state:critical"))]);
    hold.close();
    expect(hold.opened(DEMO, icons)?.places).toHaveLength(1);
  });

  it("never quotes what was stored when it does not parse", () => {
    const secret = "aws-production-root";
    const bad = (raw: string): PlaceStore => ({ getItem: () => raw, setItem: () => undefined });
    const a = loadPlaces(bad(`[{"name":"${secret}","line":"x","icon":"nope"}]`), icons).problems;
    const b = loadPlaces(bad(`{"${secret}`), icons).problems;
    expect([...a, ...b].join("\n")).not.toContain(secret);
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(1);
  });
});

describe("a closed session leaves nothing of the vault", () => {
  it("drops the path, its history, the plugins' words and the re-prompt list", async () => {
    const backend = Object.assign(new DemoBackend(), { verifyReprompt: async () => undefined });
    const hold = new SessionHold(backend);
    hold.opened(DEMO, icons);
    const q = query();
    const path = hold.pathFor(q, "personal › work › aws-production");
    path.commit("acme");
    expect(hold.currentPath).toBe(path);
    hold.registerWords("plug", { [Lang.Ru]: { host: "сервер-db-1" }, [Lang.En]: { host: "server-db-1" } });
    expect(text({ ext: "plug.host" })).toBeTruthy();
    expect(hold.reprompt.isGuarded("billing")).toBe(true);
    const pending = hold.reprompt.confirm("billing");

    hold.close();

    expect(hold.currentPath).toBeNull();
    expect(hold.isOpen).toBe(false);
    expect(() => text({ ext: "plug.host" })).toThrow();
    expect(hold.reprompt.isGuarded("billing")).toBe(false);
    expect(hold.reprompt.get()).toBeNull();
    await expect(pending).resolves.toBe(false);
    // A new session starts on a new path, without the old history.
    const again = hold.pathFor(q, "");
    expect(again).not.toBe(path);
    expect(again.get().canBack).toBe(false);
  });

  it("drops the path when there is no graph to draw from", () => {
    const hold = new SessionHold(new DemoBackend());
    hold.pathFor(query(), "acme");
    expect(hold.dropPath()).toBeNull();
    expect(hold.currentPath).toBeNull();
  });
});

describe("a revealed value never lands where it was not asked for", () => {
  const deferred = () => {
    let resolve!: (r: Revealed) => void;
    const p = new Promise<Revealed>((r) => (resolve = r));
    return { p, resolve };
  };
  const yes = () => Promise.resolve(true);
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("drops an answer that comes after a hide", async () => {
    const shown: (string | null)[] = [];
    const s = new RevealSession((v) => shown.push(v), () => true, 30_000);
    const d = deferred();
    const drop = vi.fn();
    const going = s.show(() => d.p, yes);
    await Promise.resolve();
    s.hide();
    d.resolve({ value: "secret-A", drop });
    await expect(going).resolves.toBe(false);
    expect(drop).toHaveBeenCalledOnce();
    expect(shown).not.toContain("secret-A");
  });

  it("shows only the latest ask: A's late answer never shows in place of B", async () => {
    const shown: (string | null)[] = [];
    const s = new RevealSession((v) => shown.push(v), () => true, 30_000);
    const a = deferred();
    const b = deferred();
    const dropA = vi.fn();
    const fetchA = vi.fn(() => a.p);
    const first = s.show(fetchA, yes);
    // A's ask is out (past the re-prompt) before B's starts.
    await vi.waitFor(() => expect(fetchA).toHaveBeenCalled());
    const second = s.show(() => b.p, yes);
    b.resolve({ value: "secret-B", drop: vi.fn() });
    await expect(second).resolves.toBe(true);
    a.resolve({ value: "secret-A", drop: dropA });
    await expect(first).resolves.toBe(false);
    expect(dropA).toHaveBeenCalledOnce();
    expect(shown.filter((v) => v !== null)).toEqual(["secret-B"]);
  });

  it("drops an answer that comes while the window has no focus, and after the field is gone", async () => {
    const shown: (string | null)[] = [];
    let focused = false;
    const s = new RevealSession((v) => shown.push(v), () => focused, 30_000);
    const drop = vi.fn();
    await expect(s.show(() => Promise.resolve({ value: "x", drop }), yes)).resolves.toBe(false);
    expect(drop).toHaveBeenCalledOnce();
    focused = true;
    const d = deferred();
    const going = s.show(() => d.p, yes);
    await Promise.resolve();
    s.dispose();
    const drop2 = vi.fn();
    d.resolve({ value: "y", drop: drop2 });
    await expect(going).resolves.toBe(false);
    expect(drop2).toHaveBeenCalledOnce();
    expect(shown.filter((v) => v !== null)).toEqual([]);
    await expect(s.show(() => d.p, yes)).rejects.toThrow();
  });

  it("hides itself after its time and lets the value go", async () => {
    const shown: (string | null)[] = [];
    const s = new RevealSession((v) => shown.push(v), () => true, 1000);
    const drop = vi.fn();
    await s.show(() => Promise.resolve({ value: "v", drop }), yes);
    expect(shown.at(-1)).toBe("v");
    vi.advanceTimersByTime(1000);
    expect(shown.at(-1)).toBeNull();
    expect(drop).toHaveBeenCalledOnce();
  });

  it("knows a lock from a failure", () => {
    expect(isLockedError(Object.assign(new Error("err.locked"), { code: "err.locked" }))).toBe(true);
    expect(isLockedError(new Error("network down"))).toBe(false);
  });
});

describe("the re-prompt", () => {
  const make = (verify?: (id: string, pw: string) => Promise<void>) => {
    const r = new Reprompt(verify);
    r.setGuarded(["billing"]);
    return r;
  };

  it("fetches nothing of a guarded item until the password is checked", async () => {
    const verify = vi.fn(async (_id: string, pw: string) => {
      if (pw !== "right") throw Object.assign(new Error("err.badPassword"), { code: "err.badPassword" });
    });
    const r = make(verify);
    const shown: (string | null)[] = [];
    const s = new RevealSession((v) => shown.push(v), () => true, 30_000);
    const fetch = vi.fn(async (): Promise<Revealed> => ({ value: "4111", drop: () => undefined }));
    const going = s.show(fetch, () => r.confirm("billing"));
    await Promise.resolve();
    expect(r.get()).toMatchObject({ itemId: "billing", busy: false });
    expect(fetch).not.toHaveBeenCalled();

    await r.submit("wrong");
    expect(verify).toHaveBeenLastCalledWith("billing", "wrong");
    expect(r.get()?.error).toEqual({ key: "err.badPassword" });
    expect(fetch).not.toHaveBeenCalled();

    await r.submit("right");
    await expect(going).resolves.toBe(true);
    expect(fetch).toHaveBeenCalledOnce();
    expect(shown.at(-1)).toBe("4111");
    expect(r.get()).toBeNull();
  });

  it("asks again every time: one check opens one value", async () => {
    const r = make(async () => undefined);
    const first = r.confirm("billing");
    await r.submit("pw");
    await expect(first).resolves.toBe(true);
    void r.confirm("billing");
    expect(r.get()).not.toBeNull();
  });

  it("gives up on cancel, on another ask, and fetches nothing", async () => {
    const r = make(async () => undefined);
    const fetch = vi.fn();
    const a = r.confirm("billing").then((ok) => ok && fetch());
    const b = r.confirm("billing").then((ok) => ok && fetch());
    r.cancel();
    await Promise.all([a, b]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("lets an answer for a prompt given up meanwhile open nothing", async () => {
    let pass!: () => void;
    const r = make(() => new Promise<void>((res) => (pass = res)));
    const ask = r.confirm("billing");
    const checking = r.submit("pw");
    r.cancel();
    pass();
    await checking;
    await expect(ask).resolves.toBe(false);
  });

  it("lets unguarded items through, and leaves the check to a backend that does it itself", async () => {
    const withCheck = make(async () => undefined);
    await expect(withCheck.confirm("aws")).resolves.toBe(true);
    const daemon = make(undefined);
    expect(daemon.isGuarded("billing")).toBe(true);
    expect(daemon.mustAsk("billing")).toBe(false);
    await expect(daemon.confirm("billing")).resolves.toBe(true);
  });

  it("takes the guarded items from the catalogue, and uses the backend's check", async () => {
    const verify = vi.fn(async () => undefined);
    const backend: Backend = Object.assign(new DemoBackend(), { verifyReprompt: verify });
    const hold = new SessionHold(backend);
    hold.opened(DEMO, icons);
    expect(DEMO.items.filter((i) => i.reprompt).every((i) => hold.reprompt.mustAsk(i.id))).toBe(true);
    const ask = hold.reprompt.confirm("billing");
    await hold.reprompt.submit("pw");
    await expect(ask).resolves.toBe(true);
    expect(verify).toHaveBeenCalledWith("billing", "pw");
  });
});
