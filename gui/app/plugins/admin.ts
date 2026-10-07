// The plugins as the window manages them, over the daemon: the manifests,
// the catalogue, its sources, and every change of them (Tauri's plugin_*
// commands). What the daemon says is read once, here, into the core's types;
// a field that does not read stops it rather than shows half a plugin.
import { invoke } from "@tauri-apps/api/core";
import {
  ICONS,
  type InstalledPlugin,
  type PluginAdminWrite,
  type PluginOffer,
  type Text,
  type Words,
  PluginAdminOp,
  parsePluginOrigin,
  parsePluginPermission,
  validSource,
} from "@keyward/core";
import type { CatalogEntry, Manifest } from "./types";

/// The built-in plugins' dictionaries, where they live: with the plugin.
const DICTIONARIES = import.meta.glob<Record<string, string>>("../../../crates/plugins/*/i18n/*.json", { eager: true, import: "default" });

/// A plugin's words in both languages; `undefined` for one that has none.
export function wordsOf(plugin: string): Words | undefined {
  const ru = DICTIONARIES[`../../../crates/plugins/${plugin}/i18n/ru.json`];
  const en = DICTIONARIES[`../../../crates/plugins/${plugin}/i18n/en.json`];
  if (!ru && !en) return undefined;
  if (!ru || !en) throw new Error(`the plugin "${plugin}" has a dictionary in one language only`);
  return { ru, en };
}

/// An icon the window has; a plugin's own name it does not have is drawn as
/// the plugins' general one, as the rail always did.
const iconOf = (name: string) => (ICONS.has(name) ? name : "grid");

const str = (v: unknown, what: string): string => {
  if (typeof v !== "string") throw new Error(`the daemon gave ${what} that is not text`);
  return v;
};

/// boundary: a manifest as the daemon gives it.
export function installedOf(m: Manifest): InstalledPlugin {
  const words = wordsOf(m.id);
  // The description is a key of the plugin's dictionary where it has one.
  const description: Text = words && m.description in words.ru ? { ext: `${m.id}.${m.description}` } : { raw: m.description };
  return {
    id: str(m.id, "a plugin's id"),
    title: m.title || m.id,
    icon: iconOf(m.icon),
    version: str(m.version, `the version of "${m.id}"`),
    description,
    origin: parsePluginOrigin(m.origin),
    enabled: m.enabled === true,
    permissions: (m.permissions ?? []).map(parsePluginPermission),
    unverified: m.unverified === true,
    added: (m.added_permissions ?? []).map(parsePluginPermission),
    revoked: m.revoked_reason ?? null,
    ...(words ? { words } : {}),
  };
}

/// boundary: a catalogue entry as the daemon gives it.
export function offerOf(e: CatalogEntry): PluginOffer {
  if (!validSource(e.source)) throw new Error(`the catalogue entry "${e.id}" came from "${e.source}", which is no source`);
  const fp = e.fingerprint;
  const what = `the catalogue entry "${e.id}"`;
  if (typeof e.size !== "number" || !Number.isFinite(e.size)) throw new Error(`${what} has a size that is not a number`);
  // The daemon says "" where there is nothing: no publisher, no version
  // installed, no package address (the id stands for it then).
  const url = str(e.url ?? "", `the address of ${what}`);
  const publisher = str(e.publisher ?? "", `the publisher of ${what}`);
  const have = str(e.installed_version ?? "", `the installed version of ${what}`);
  return {
    id: str(e.id, "a catalogue entry's id"),
    title: e.title || e.id,
    icon: iconOf(e.icon),
    description: str(e.description, `the description of ${what}`),
    homepage: str(e.homepage, `the home page of ${what}`),
    source: e.source,
    from: url || e.id,
    version: str(e.version, `the version of ${what}`),
    permissions: e.permissions.map(parsePluginPermission),
    size: e.size,
    installed: e.installed === true,
    installedVersion: have || null,
    update: e.update === true,
    publisher: publisher || null,
    signed: e.signed === true,
    trusted: e.trusted === undefined ? null : e.trusted,
    fingerprint: fp === undefined ? [] : Array.isArray(fp) ? fp.map((w) => str(w, `the fingerprint of ${what}`)) : fp.split(/[\s-]+/).filter(Boolean),
    revoked: e.revoked ? (e.reason ?? "") : null,
  };
}

export async function pluginList(): Promise<InstalledPlugin[]> {
  return (await invoke<Manifest[]>("plugins")).map(installedOf);
}

export async function pluginCatalog(refresh: boolean): Promise<{ offers: PluginOffer[]; stale: boolean }> {
  const entries = await invoke<CatalogEntry[]>("plugin_catalog", { refresh });
  return { offers: entries.map(offerOf), stale: entries.some((e) => e.stale === true) };
}

export async function pluginSources(): Promise<string[]> {
  return (await invoke<string[]>("plugin_sources", { set: null })).map((s) => str(s, "a source"));
}

/// One change of plugins; the id of a plugin it installed, or `null`.
export async function pluginAdmin(w: PluginAdminWrite): Promise<string | null> {
  switch (w.op) {
    case PluginAdminOp.Enable:
    case PluginAdminOp.Disable:
      await invoke("plugin_enable", { id: w.id, on: w.op === PluginAdminOp.Enable });
      return null;
    case PluginAdminOp.Remove:
      await invoke("plugin_remove", { id: w.id });
      return null;
    case PluginAdminOp.Install:
      return installedOf(await invoke<Manifest>("plugin_install", { path: w.from })).id;
    case PluginAdminOp.InstallFile: {
      const path = await invoke<string | null>("plugin_pick", { archive: w.archive });
      return path === null ? null : installedOf(await invoke<Manifest>("plugin_install", { path })).id;
    }
    case PluginAdminOp.Trust:
      await invoke("plugin_trust", { publisher: w.publisher });
      return null;
    case PluginAdminOp.Sources:
      for (const s of w.set) if (!validSource(s)) throw new Error(`"${s}" is no source`);
      await invoke<string[]>("plugin_sources", { set: w.set });
      return null;
    case PluginAdminOp.Refresh:
      await invoke("plugin_catalog", { refresh: true });
      return null;
  }
}
