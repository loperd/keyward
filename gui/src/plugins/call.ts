import { useEffect, useState } from "react";
import { tMaybe } from "../i18n";
import { firstPlugins, knownPlugins, watchPlugins } from "../../app/plugins/call";
import type { Manifest } from "../../app/plugins/types";

// The calls and the list of plugins live with the new window (gui/app); the
// old window keeps only what needs React and its own dictionary.
export * from "../../app/plugins/call";

/// The plugins' manifests. Until the daemon answers, an empty list: the rail
/// draws its own sections and does not wait.
export function usePlugins(): Manifest[] {
  const [list, setList] = useState<Manifest[]>(() => knownPlugins() ?? []);

  useEffect(() => {
    const stop = watchPlugins(setList);
    let alive = true;
    if (!knownPlugins()) {
      void firstPlugins().then((plugins) => {
        if (alive) setList(plugins);
      });
    }
    return () => {
      alive = false;
      stop();
    };
  }, []);

  return list;
}

/// A section's caption in the rail: the translation when there is one,
/// otherwise the name from the manifest. A plugin's section may be named for
/// what it shows ("Routes") rather than for the plugin ("SSH").
export function pluginTitle(manifest: Manifest): string {
  return tMaybe(`plugin.${manifest.id}.title`, manifest.title);
}

/// The caption of a block in the settings: a section and its settings may be
/// named differently — "Routes" in the rail, "SSH" in the settings.
export function pluginSettingsTitle(manifest: Manifest): string {
  return tMaybe(`plugin.${manifest.id}.settings`, pluginTitle(manifest));
}
