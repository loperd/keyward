import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { tMaybe } from "../i18n";
import type { CatalogEntry, Manifest } from "./types";

export type { CatalogEntry, Manifest, Origin, Permission } from "./types";

/// A conversation with a plugin: one envelope for all of them. The core does
/// not read into the operation, so the names of the operations and the fields
/// of the payload are the same snake_case the former commands had.
///
/// The command's argument is called `action` rather than `op`: the name `op` is
/// already taken by the envelope's internal tag on the daemon's side.
export function call<T>(plugin: string, op: string, payload?: unknown): Promise<T> {
  return invoke<T>("plugin_call", { plugin, action: op, payload: payload ?? null });
}

/// A call that needs values of an item's own fields — unseal keys, say. The
/// screen names the fields; the daemon reads them (with Touch ID, as revealing
/// does) and puts them into `payload[into]`. The values never reach the window.
export function callWithFields<T>(
  plugin: string,
  op: string,
  payload: Record<string, unknown>,
  fill: { entryId: string; fields: string[]; into: string },
): Promise<T> {
  return invoke<T>("plugin_call_with_fields", { plugin, action: op, payload, ...fill });
}

/*
  The list of plugins is no longer a "once per launch" affair.

  The set was compiled into the daemon at build time, and the manifests could be
  asked for once. Now a plugin is installed and removed from the window, and a
  switched-off one disappears from the rail — which means that after every such
  operation the list has to be re-read everywhere it is shown, without
  restarting the application.
*/
let cached: Manifest[] | null = null;
let asked: Promise<Manifest[]> | null = null;
const watchers = new Set<(list: Manifest[]) => void>();

/// `null` means the daemon did not answer. That is not the same as "there are
/// no plugins": an empty list from a living daemon may be remembered, silence
/// may not.
async function fetchPlugins(): Promise<Manifest[] | null> {
  try {
    return await invoke<Manifest[]>("plugins");
  } catch {
    return null;
  }
}

function same(a: Manifest[] | null, b: Manifest[]): boolean {
  return a !== null && JSON.stringify(a) === JSON.stringify(b);
}

function publish(list: Manifest[]): Manifest[] {
  // Nothing has changed, so nothing is said: the list is re-read on a timer,
  // and there is no point waking a redraw with it every few seconds.
  if (same(cached, list)) return cached ?? list;
  cached = list;
  asked = Promise.resolve(list);
  for (const watcher of watchers) watcher(list);
  return list;
}

/// Re-read the manifests and send them to everybody showing them.
export async function refreshPlugins(): Promise<Manifest[]> {
  const list = await fetchPlugins();
  // A failure does not wipe what is already shown: sections must not vanish
  // from the rail because of one unanswered request.
  return list ? publish(list) : (cached ?? []);
}

/*
  The first request is made when the daemon is sometimes not up yet: the window
  starts right after the installation, and `plugins` answers with an error at
  that moment. The error used to be remembered as an empty list for ever — and
  the plugins' sections disappeared until the window was restarted. Now silence
  is not remembered, and the attempts are repeated with a growing pause.
*/
async function fetchWithRetries(): Promise<Manifest[]> {
  for (const pause of [0, 400, 800, 1600, 3200, 5000, 5000]) {
    if (pause) await new Promise((done) => setTimeout(done, pause));
    const list = await fetchPlugins();
    if (list) return list;
  }
  return [];
}

/// The plugins' manifests. Until the daemon answers, an empty list: the rail
/// draws its own sections and does not wait.
export function usePlugins(): Manifest[] {
  const [list, setList] = useState<Manifest[]>(() => cached ?? []);

  useEffect(() => {
    watchers.add(setList);
    let alive = true;
    if (!cached) {
      asked ??= fetchWithRetries();
      void asked.then((plugins) => {
        if (cached === null) cached = plugins;
        if (alive) setList(plugins);
      });
    }
    return () => {
      alive = false;
      watchers.delete(setList);
    };
  }, []);

  return list;
}

/// Choosing a package: the system's dialogue is opened by Rust — for a
/// directory it is one window and for an archive another, and the button that
/// was pressed decides which. `null` means the dialogue was closed.
export function pickPluginPackage(archive: boolean): Promise<string | null> {
  return invoke<string | null>("plugin_pick", { archive });
}

/// Install a package. The daemon installs it **switched off**: the permissions
/// are confirmed separately, with the list of what the plugin asks for already
/// in view.
export async function installPlugin(path: string): Promise<Manifest> {
  const manifest = await invoke<Manifest>("plugin_install", { path });
  await refreshPlugins();
  return manifest;
}

/// The catalogue: what there is to install. `refresh` means go to the network
/// without fail; without it the daemon may answer from its cache, and then the
/// entries arrive with `stale: true`.
///
/// The error is not swallowed: "the catalogue is out of reach, here is the
/// cache" is `stale` on the entries rather than an exception, and since an
/// exception did happen after all, the person has to be told about it.
export function catalog(refresh = false): Promise<CatalogEntry[]> {
  return invoke<CatalogEntry[]>("plugin_catalog", { refresh });
}

/// The catalogues' addresses: with no argument, read them; with a list,
/// replace them. In both cases the daemon answers with what is written now, so
/// the answer can be put into the state as it is.
export function sources(set?: string[]): Promise<string[]> {
  return invoke<string[]>("plugin_sources", { set: set ?? null });
}

/// Trust a publisher: their key goes into the list of trusted ones, and from
/// that moment the packages they sign can be installed. An action of its own —
/// the five words of the fingerprint are checked first.
export function trustPublisher(publisher: string): Promise<void> {
  return invoke<void>("plugin_trust", { publisher });
}

/// Install from the catalogue. The package's address is taken from the entry;
/// a catalogue that did not name one leaves the daemon the `id` — it will find
/// the package in its own copy of the catalogue.
export function installEntry(entry: CatalogEntry): Promise<Manifest> {
  return installPlugin(entry.url || entry.id);
}

/// Switch on or off. Switching on is itself the consent to the permissions.
export async function enablePlugin(id: string, on: boolean): Promise<void> {
  await invoke("plugin_enable", { id, on });
  await refreshPlugins();
}

/// Remove a plugin along with its settings and its state.
export async function removePlugin(id: string): Promise<void> {
  await invoke("plugin_remove", { id });
  await refreshPlugins();
}

/// A plugin's name: the package's own, exactly as the catalogue shows it. The
/// card, the consent and the removal say this one, so that what was picked in
/// the catalogue is recognised among the installed — "SSH" in both places, not
/// "SSH" in one and a section's caption in the other.
export function pluginName(manifest: Manifest): string {
  return manifest.title || manifest.id;
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

/// A further section's caption: `plugin.<id>.section.<section>`, and failing
/// that the section's own name.
export function pluginSectionTitle(manifest: Manifest, section: string): string {
  return tMaybe(`plugin.${manifest.id}.section.${section}`, section);
}
