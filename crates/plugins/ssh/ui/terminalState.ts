import { useEffect, useSyncExternalStore } from "react";
import { call } from "@keyward/plugins/call";
import type { HealthReport, TermInfo, TermState } from "./types";

/// What is open in the terminal's section.
///
/// The hosts live in the section's column and the shells in the main one:
/// different branches of the tree, with no common parent. The core knows
/// nothing of terminals, so the choice lies here, in a store of the plugin's
/// own. It outlives the section: leaving it and coming back finds the same
/// tabs, and each re-attaches to its shell, which the plugin kept alive.
function store<T>(initial: T) {
  let value = initial;
  const listeners = new Set<() => void>();
  return {
    get: () => value,
    set(next: T) {
      if (next === value) return;
      value = next;
      for (const l of listeners) l();
    },
    use(): T {
      return useSyncExternalStore(
        (l) => {
          listeners.add(l);
          return () => {
            listeners.delete(l);
          };
        },
        () => value,
      );
    },
  };
}

/// Where a new shell goes. A key the page named wins over the routes.
export type Destination = { entry_id?: string; host: string; port?: number | null; user?: string | null };

/// One tab: a shell being opened (`destination`) or one that exists
/// (`session`). `key` is the page's own, stable from the first frame.
export type Tab = {
  key: string;
  /// Bumped by "reconnect": the tab's terminal starts over with a new shell.
  epoch?: number;
  destination?: Destination;
  session?: string;
  info?: TermInfo;
  state: TermState;
};

export const OVERVIEW = "overview";

const tabsStore = store<Tab[]>([]);
const activeStore = store<string>(OVERVIEW);
/// The connect dialogue: `null` is closed, a destination is its first guess.
const connectStore = store<Destination | null>(new URLSearchParams(window.location.search).has("connect") ? { host: "" } : null);

export const useTabs = tabsStore.use;
export const useActive = activeStore.use;
export const setActive = (key: string) => activeStore.set(key);
export const useConnect = connectStore.use;
export const setConnect = (d: Destination | null) => connectStore.set(d);

let counter = 0;
function newKey(): string {
  counter += 1;
  return `t${Date.now().toString(36)}${counter}`;
}

/// Opens a new tab for a destination and shows it.
export function openTab(destination: Destination) {
  const tab: Tab = { key: newKey(), destination, state: { kind: "connecting" } };
  tabsStore.set([...tabsStore.get(), tab]);
  activeStore.set(tab.key);
}

/// Adds tabs for shells the plugin has that no tab shows — after the section
/// was left, or the window reloaded.
export function adoptSessions(sessions: (TermInfo & { state: TermState })[]) {
  const tabs = tabsStore.get();
  const known = new Set(tabs.map((t) => t.session).filter(Boolean));
  const fresh = sessions
    .filter((s) => !known.has(s.id) && s.state.kind !== "closed")
    .map((s) => ({ key: newKey(), session: s.id, info: s, state: s.state }) satisfies Tab);
  if (fresh.length) tabsStore.set([...tabs, ...fresh]);
}

export function patchTab(key: string, patch: Partial<Tab>) {
  tabsStore.set(tabsStore.get().map((t) => (t.key === key ? { ...t, ...patch } : t)));
}

export function dropTab(key: string) {
  const tabs = tabsStore.get();
  const at = tabs.findIndex((t) => t.key === key);
  const rest = tabs.filter((t) => t.key !== key);
  tabsStore.set(rest);
  if (activeStore.get() === key) {
    const next = rest[Math.min(at, rest.length - 1)];
    activeStore.set(next ? next.key : OVERVIEW);
  }
}

/// The vault was locked: the plugin closed every shell, so the tabs go too.
export function forgetTabs() {
  tabsStore.set([]);
  activeStore.set(OVERVIEW);
}

/* The keys' health, read by the section's column, the overview and the
   routes alike. One poll for all of them, running while anybody shows it. */
const healthStore = store<HealthReport | null>(null);
let watchers = 0;
let timer: ReturnType<typeof setTimeout> | null = null;

async function pollHealth() {
  // One loop, whoever asked: a poll asked out of turn replaces the waiting one.
  if (timer) clearTimeout(timer);
  timer = null;
  try {
    const report = await call<HealthReport>("ssh", "health");
    healthStore.set(report);
    // A round in progress is watched closely; a quiet board rarely.
    if (watchers > 0) timer = setTimeout(pollHealth, report.running ? 700 : 15000);
  } catch {
    if (watchers > 0) timer = setTimeout(pollHealth, 15000);
  }
}

export function useHealth(): HealthReport | null {
  useEffect(() => {
    watchers += 1;
    if (watchers === 1 && !timer) void pollHealth();
    return () => {
      watchers -= 1;
      if (watchers === 0 && timer) {
        clearTimeout(timer);
        timer = null;
      }
    };
  }, []);
  return healthStore.use();
}

/// Checks the keys now — every key, or one — and shows the result.
export async function runHealth(entryId?: string): Promise<void> {
  const current = healthStore.get();
  if (current) healthStore.set({ ...current, running: true });
  try {
    healthStore.set(await call<HealthReport>("ssh", "health_run", entryId ? { entry_id: entryId } : null));
  } finally {
    void pollHealth();
  }
}

/// Starts a tab over with a new shell to the same place.
export function reconnectTab(key: string) {
  tabsStore.set(
    tabsStore.get().map((t) => {
      if (t.key !== key) return t;
      const destination: Destination | undefined = t.info
        ? { entry_id: t.info.entry_id, host: t.info.host, port: t.info.port, user: t.info.user }
        : t.destination;
      return { ...t, destination, session: undefined, state: { kind: "connecting" }, epoch: (t.epoch ?? 0) + 1 };
    }),
  );
}

/* The terminal's font size, the same in every tab and remembered on this
   machine. The grid's sizes and a step between them. */
export const FONT_SIZES = [12, 13, 14, 16, 18, 20];

function savedFont(): number {
  try {
    const v = Number(localStorage.getItem("kw.term.font"));
    return FONT_SIZES.includes(v) ? v : 13;
  } catch {
    return 13;
  }
}

const fontStore = store<number>(savedFont());
export const useFontSize = fontStore.use;

export function stepFont(delta: -1 | 0 | 1) {
  const now = fontStore.get();
  const at = FONT_SIZES.indexOf(now);
  const next = delta === 0 ? 13 : FONT_SIZES[Math.max(0, Math.min(FONT_SIZES.length - 1, at + delta))];
  fontStore.set(next);
  try {
    localStorage.setItem("kw.term.font", String(next));
  } catch {
    /* it works without storage too */
  }
}

/* Closing a tab ends its shell; leaving the section does not. The tab's
   terminal registers how to end its shell while it is mounted. */
const closers = new Map<string, () => Promise<void>>();

export function registerCloser(key: string, close: () => Promise<void>): () => void {
  closers.set(key, close);
  return () => {
    if (closers.get(key) === close) closers.delete(key);
  };
}

export async function closeTab(key: string) {
  const close = closers.get(key);
  dropTab(key);
  if (!close) return;
  try {
    await close();
  } catch {
    // A shell that is already gone has nothing left to close.
  }
}
