// How a plugin's declared screen talks to its plugin: every operation goes
// through the backend (sealed, in the desktop app), its reply is read once
// (`screenReader`) and done — a route to go to, a drawer, a dialogue, a
// toast, the screen asked again. A refusal is reported, never swallowed.
import { createContext, useCallback, useContext, useMemo, useRef } from "react";
import { text } from "../../i18n";
import { type ScreenAction, type ScreenReader, type ScreenReply, PluginLane, screenReader } from "../../plugin/screen";
import { ICONS } from "../Icons";
import { type Core, useCore } from "../marks";
import { ToastKind } from "../toasts";

export type ScreenCtx = {
  /// The node the screen is drawn over, and whose plugin it is.
  node: string;
  plugin: string;
  reader: ScreenReader;
  /// Carries out an action and does what its reply says; `null` when it was
  /// refused (and reported).
  run: (a: ScreenAction, form?: Readonly<Record<string, string>> | null) => Promise<ScreenReply | null>;
  /// An operation whose reply is read but not done, and whose refusal is
  /// the caller's: a terminal's keystrokes, and its long poll on the output
  /// lane.
  call: (op: string, payload: unknown, lane: PluginLane) => Promise<ScreenReply>;
  /// Moves on every refresh a reply asks for.
  epoch: number;
};

export const ScreenContext = createContext<ScreenCtx | null>(null);

export function useScreen(): ScreenCtx {
  const c = useContext(ScreenContext);
  if (!c) throw new Error("a part of a plugin's screen was drawn outside its screen");
  return c;
}

/// The reader of a plugin's answers, with its words.
export function useReader(plugin: string): ScreenReader {
  const { dir } = useCore();
  const words = dir.contributions.find((c) => c.id === plugin)?.words;
  // The dictionaries are the plugin's files, the same objects from one
  // reading of the places to the next.
  return useMemo(() => screenReader(plugin, { words, icons: ICONS }), [plugin, words?.ru, words?.en]); // eslint-disable-line react-hooks/exhaustive-deps
}

/// Does what a reply says, over `node`.
export function applyReply(core: Core, node: string, plugin: string, r: ScreenReply): void {
  const { screens, store, dir } = core;
  if (r.go !== undefined) {
    // A route a place opens is that place's: the path steps there.
    const target = dir.contributions.find((c) => c.id === plugin)?.screens?.[r.go];
    if (target && target !== node && dir.has(target)) {
      screens.open(target, plugin, r.go);
      store.go(target);
    } else screens.patch(node, plugin, { route: r.go, drawer: null });
  }
  const patch: Parameters<typeof screens.patch>[2] = {};
  if (r.drawer) patch.drawer = r.drawer;
  if (r.closeDrawer) patch.drawer = null;
  if (r.dialog) patch.dialog = r.dialog;
  if (r.closeDialog) patch.dialog = null;
  if (Object.keys(patch).length) screens.patch(node, plugin, patch);
  if (r.refresh) screens.refresh(node);
  if (r.toast) core.toast(ToastKind.Ok, text(r.toast));
}

/// The screen context for a node and its plugin.
export function useScreenCtx(node: string, plugin: string, epoch: number): ScreenCtx {
  const core = useCore();
  const reader = useReader(plugin);
  const { backend } = core;
  // The graph is built anew on every reading of the catalogue; an action
  // reads the one standing when its reply comes, and a screen's loads are
  // not asked again for it.
  const now = useRef(core);
  now.current = core;
  const run = useCallback(
    async (a: ScreenAction, form: Readonly<Record<string, string>> | null = null): Promise<ScreenReply | null> => {
      try {
        if (!backend.pluginRun) throw new Error(`this app cannot carry out the plugin "${plugin}"'s actions`);
        const r = reader.reply(await backend.pluginRun(plugin, { op: a.op, payload: a.payload, form }, PluginLane.Input), a.op);
        applyReply(now.current, node, plugin, r);
        return r;
      } catch (e) {
        now.current.report(e);
        return null;
      }
    },
    [backend, reader, node, plugin],
  );
  const call = useCallback(
    async (op: string, payload: unknown, lane: PluginLane): Promise<ScreenReply> => {
      if (!backend.pluginRun) throw new Error(`this app cannot carry out the plugin "${plugin}"'s actions`);
      return reader.reply(await backend.pluginRun(plugin, { op, payload, form: null }, lane), op);
    },
    [backend, reader, plugin],
  );
  return useMemo(() => ({ node, plugin, reader, run, call, epoch }), [node, plugin, reader, run, call, epoch]);
}
