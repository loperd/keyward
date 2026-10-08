// The demo's plugins, as Settings › Plugins shows them: two built in and on,
// one built in and off, one installed from a package past the catalogue whose
// update asks for more, and a catalogue with an update, a plugin to install
// and one whose publisher is still to be trusted. Kept in memory; every
// change answers as the daemon would.
import { type InstalledPlugin, type PluginAdminWrite, type PluginOffer, PluginAdminOp, PluginOrigin, PluginPermission as P } from "./plugin/admin";

const d = (key: string) => ({ ext: `demo.${key}` });

/// The demo's words for its plugins, in both languages.
export const PLUGIN_WORDS: Record<string, { ru: string; en: string }> = {
  plugSsh: { ru: "Терминал на серверы по ключам хранилища", en: "A terminal to servers by the vault's keys" },
  plugKube: { ru: "Кластеры на серверах, до которых достают ключи", en: "Clusters on the servers the keys reach" },
  plugVault: { ru: "Секреты HashiCorp Vault рядом с записями", en: "HashiCorp Vault secrets beside the items" },
  plugNotes: { ru: "Заметки из Markdown-папки", en: "Notes from a Markdown folder" },
};

const INSTALLED: InstalledPlugin[] = [
  { id: "ssh", title: "SSH", icon: "terminal", version: "0.2.0", description: d("plugSsh"), origin: PluginOrigin.Builtin, enabled: true, permissions: [P.Entries, P.ItemsWrite, P.Notices, P.SshSign, P.Network], unverified: false, added: [], revoked: null },
  { id: "kube", title: "Kubernetes", icon: "cube", version: "0.2.0", description: d("plugKube"), origin: PluginOrigin.Builtin, enabled: true, permissions: [P.Entries, P.Items, P.ItemsWrite, P.Secrets, P.Notices, P.SshSign, P.Network], unverified: false, added: [], revoked: null },
  { id: "hashicorp", title: "HashiCorp Vault", icon: "vault", version: "0.2.0", description: d("plugVault"), origin: PluginOrigin.Builtin, enabled: true, permissions: [P.Entries, P.Items, P.ItemsWrite, P.Secrets, P.Notices, P.Network, P.Clipboard], unverified: false, added: [], revoked: null },
  { id: "notes-sync", title: "Notes sync", icon: "note", version: "1.3.0", description: d("plugNotes"), origin: PluginOrigin.External, enabled: false, permissions: [P.Items, P.ItemsWrite, P.Network], unverified: true, added: [P.Network], revoked: null },
];

const SOURCE = "https://plugins.keyward.example/index.json";
const OFFERS: PluginOffer[] = [
  { id: "notes-sync", title: "Notes sync", icon: "note", description: "Notes from a Markdown folder", homepage: "https://notes.demo.example", source: SOURCE, from: "https://plugins.keyward.example/notes-sync-1.4.0.tar.gz", version: "1.4.0", permissions: [P.Items, P.ItemsWrite, P.Network], size: 2_400_000, installed: true, installedVersion: "1.3.0", update: true, publisher: "keyward", signed: true, trusted: true, fingerprint: ["amber", "harbor", "lilac", "tundra", "velvet"], revoked: null },
  { id: "totp-export", title: "TOTP export", icon: "clock", description: "Codes to an authenticator app, by QR", homepage: "https://totp.demo.example", source: SOURCE, from: "https://plugins.keyward.example/totp-export-0.3.1.tar.gz", version: "0.3.1", permissions: [P.Items, P.Secrets], size: 870_000, installed: false, installedVersion: null, update: false, publisher: "keyward", signed: true, trusted: true, fingerprint: ["amber", "harbor", "lilac", "tundra", "velvet"], revoked: null },
  { id: "grafana", title: "Grafana", icon: "pulse", description: "Dashboards whose tokens live in the vault", homepage: "https://grafana.demo.example", source: SOURCE, from: "https://plugins.keyward.example/grafana-0.9.0.tar.gz", version: "0.9.0", permissions: [P.Entries, P.Secrets, P.Network], size: 5_100_000, installed: false, installedVersion: null, update: false, publisher: "dashboards-inc", signed: true, trusted: false, fingerprint: ["copper", "meadow", "orbit", "sable", "willow"], revoked: null },
];

/// The demo's plugin state, changed as the daemon would change it.
export class DemoPlugins {
  private installed = structuredClone(INSTALLED);
  private offers = structuredClone(OFFERS);
  private sources = [SOURCE];
  private trusted = new Set(["keyward"]);

  list(): InstalledPlugin[] {
    return structuredClone(this.installed);
  }
  catalog(): { offers: PluginOffer[]; stale: boolean } {
    const have = new Map(this.installed.map((p) => [p.id, p.version]));
    const offers = this.sources.includes(SOURCE)
      ? this.offers.map((o) => {
          const v = have.get(o.id) ?? null;
          return { ...o, installed: v !== null, installedVersion: v, update: v !== null && v !== o.version, trusted: o.publisher ? this.trusted.has(o.publisher) : null };
        })
      : [];
    return { offers, stale: false };
  }
  listSources(): string[] {
    return [...this.sources];
  }

  /// One change; the id of a plugin it installed, or `null`.
  change(w: PluginAdminWrite): string | null {
    const find = (id: string) => this.installed.find((p) => p.id === id) ?? null;
    switch (w.op) {
      case PluginAdminOp.Enable:
      case PluginAdminOp.Disable: {
        const p = find(w.id);
        if (!p) throw new Error(`no plugin "${w.id}" in the demo`);
        p.enabled = w.op === PluginAdminOp.Enable;
        // Turning it on is the consent: what an update added is agreed to.
        if (p.enabled) p.added = [];
        return null;
      }
      case PluginAdminOp.Remove: {
        const p = find(w.id);
        if (!p || p.origin !== PluginOrigin.External) throw new Error(`"${w.id}" is no plugin the demo can remove`);
        this.installed = this.installed.filter((x) => x !== p);
        return null;
      }
      case PluginAdminOp.Install: {
        const o = this.offers.find((x) => x.from === w.from);
        if (!o) throw new Error(`the demo's catalogue has no package at "${w.from}"`);
        if (o.publisher && !this.trusted.has(o.publisher)) throw new Error(`the demo does not trust "${o.publisher}" yet`);
        const was = find(o.id);
        const next: InstalledPlugin = { id: o.id, title: o.title, icon: o.icon, version: o.version, description: { raw: o.description }, origin: PluginOrigin.External, enabled: false, permissions: o.permissions, unverified: !o.signed, added: was ? o.permissions.filter((x) => !was.permissions.includes(x)) : [], revoked: null };
        this.installed = [...this.installed.filter((x) => x.id !== o.id), next];
        return o.id;
      }
      case PluginAdminOp.InstallFile:
        // The demo has no disk: the picker is closed at once.
        return null;
      case PluginAdminOp.Trust:
        this.trusted.add(w.publisher);
        return null;
      case PluginAdminOp.Sources:
        this.sources = [...w.set];
        return null;
      case PluginAdminOp.Refresh:
        return null;
    }
  }
}
