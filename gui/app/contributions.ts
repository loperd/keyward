/// <reference types="vite/client" />
// The plugins' places on the new window's path. Each enabled plugin whose
// manifest says `places` is asked for them on its sealed road (the same one
// its declared screens travel); the answer is checked and made into a
// contribution by the core (`contributionOf`), with the plugin's own
// dictionary. A plugin brings no code to the window: what it can do is its
// verbs, which come back here as its actions. One plugin that does not
// answer stands loud in its place rather than taking the window down.
import { invoke } from "@tauri-apps/api/core";
import {
  CORE_VERBS,
  DOCUMENT_VERBS,
  ICONS,
  contributionOf,
  failedContribution,
  withWriteVerbs,
  type Contribution,
  type DeclaredPlaces,
  type PluginCall,
} from "@keyward/core";
import { act, places } from "./declared/channel";
import type { Manifest } from "./plugins/types";
import { wordsOf } from "./plugins/admin";

export type PluginPlaces = {
  contributions: Contribution[];
  /// The soonest any plugin asked to be asked again, or `null`.
  refreshMs: number | null;
};

/// The places of every enabled plugin that declares them.
export async function pluginPlaces(): Promise<PluginPlaces> {
  const list = await invoke<Manifest[]>("plugins");
  const ours = list.filter((m) => m.enabled && m.places);
  const answers = await Promise.all(
    ours.map(async (m) => {
      try {
        return { m, d: (await places(m.id)) as DeclaredPlaces };
      } catch (e) {
        return { m, e };
      }
    }),
  );
  const taken = new Set<string>([...withWriteVerbs(CORE_VERBS).map((v) => v.id), ...DOCUMENT_VERBS]);
  const contributions: Contribution[] = [];
  let refreshMs: number | null = null;
  for (const a of answers) {
    const icon = ICONS.has(a.m.icon) ? a.m.icon : "info";
    if ("e" in a) {
      console.error(`the plugin "${a.m.id}" did not give its places`, a.e);
      contributions.push(failedContribution(a.m.id, a.m.title, icon, reasonOf(a.e)));
      continue;
    }
    try {
      const c = contributionOf(a.m.id, a.d, { words: wordsOf(a.m.id), icons: ICONS, taken });
      for (const v of c.verbs ?? []) taken.add(v.id);
      contributions.push(c);
      const ms = a.d.refresh_ms;
      if (typeof ms === "number" && ms > 0) refreshMs = refreshMs === null ? ms : Math.min(refreshMs, ms);
    } catch (e) {
      console.error(`the plugin "${a.m.id}" declared places that do not hold together`, e);
      contributions.push(failedContribution(a.m.id, a.m.title, icon, reasonOf(e)));
    }
  }
  return { contributions, refreshMs };
}

/// Carries out one of a plugin's actions; the reply as it came, for the core
/// to read (a screen to go to, a drawer, a dialogue, a toast).
export async function pluginAct(call: PluginCall): Promise<unknown> {
  return act(call.plugin, call.op, call.payload);
}

const reasonOf = (e: unknown) => (e instanceof Error ? e.message : String(e));
