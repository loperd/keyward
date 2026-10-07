// The Plugins page under Settings: the plugins installed here, each a step of
// its own with what it asks for and whether it is on, then what the
// catalogue offers, its sources, and the ways to install a package. What
// changes anything — turning one on (the consent to what it asks), off,
// removing it, installing, trusting a publisher, the sources — is a verb with
// a preview (verbs/plugins.ts). Pure.
import type { Key, Text } from "../i18n";
import { type Block, type DocSpec, Hue, LeadTile, type MarkSpec, type Section, SkeletonKind } from "../doc/spec";
import { Level } from "../model/types";
import type { Entry } from "../path/directory";
import { type InstalledPlugin, type PluginAdmin, type PluginOffer, PluginOrigin, PluginPermission, WEIGHTY, hostOf, humanSize, sortPermissions } from "../plugin/admin";
import { pageId, SETTINGS_ID, SettingsPage } from "./pages";

const k = (key: Key, args?: Record<string, string | number | Text>): Text => (args ? { key, args } : { key });
const raw = (s: string): Text => ({ raw: s });

export const PLUGINS_PAGE = pageId(SettingsPage.Plugins);
export const installedId = (id: string) => `${PLUGINS_PAGE}/${id}`;
export const offerId = (o: PluginOffer) => `${PLUGINS_PAGE}/offer/${o.source}|${o.id}`;

/// The verbs' words, by id: what the pages offer.
export enum PluginVerb {
  Enable = "enable",
  Disable = "disable",
  Uninstall = "uninstall",
  Install = "install",
  Trust = "trust",
  InstallFile = "install file",
  InstallAddress = "install address",
  AddSource = "add source",
  RemoveSource = "remove source",
  Refresh = "refresh catalogue",
}

const PERMISSION_WORD: Record<PluginPermission, Key> = {
  [PluginPermission.Entries]: "plug.perm.entries",
  [PluginPermission.Items]: "plug.perm.items",
  [PluginPermission.ItemsWrite]: "plug.perm.itemsWrite",
  [PluginPermission.Notices]: "plug.perm.notices",
  [PluginPermission.Clipboard]: "plug.perm.clipboard",
  [PluginPermission.SshSign]: "plug.perm.sshSign",
  [PluginPermission.Secrets]: "plug.perm.secrets",
  [PluginPermission.Keychain]: "plug.perm.keychain",
  [PluginPermission.Network]: "plug.perm.network",
};
export const permissionWord = (p: PluginPermission): Text => k(PERMISSION_WORD[p]);

/// How an installed plugin stands, and why.
export function pluginState(p: InstalledPlugin): MarkSpec {
  if (p.revoked !== null) return { level: Level.Critical, text: k("plug.state.revoked", { reason: p.revoked || k("plug.noReason") }) };
  if (p.added.length) return { level: Level.Action, text: k("plug.state.asksMore", { n: p.added.length }) };
  if (!p.enabled) return { level: Level.Unknown, text: k("plug.state.off") };
  if (p.unverified) return { level: Level.Warning, text: k("plug.state.unverified") };
  return { level: Level.Healthy, text: k("plug.state.on") };
}

/// How an offer stands: what can be done with it.
export function offerState(o: PluginOffer): MarkSpec {
  if (o.revoked !== null) return { level: Level.Critical, text: k("plug.offer.revoked", { reason: o.revoked || k("plug.noReason") }) };
  if (o.trusted === false) return { level: Level.Warning, text: k("plug.offer.untrusted") };
  if (o.update) return { level: Level.Action, text: k("plug.offer.update", { from: o.installedVersion ?? "", to: o.version }) };
  if (o.installed) return { level: Level.Healthy, text: k("plug.offer.installed") };
  return { level: Level.Unknown, text: k("plug.offer.available") };
}

/// What it asks for, as lines: the weighty ones in their colour, what an
/// update added marked so.
function permissions(ps: readonly PluginPermission[], added: readonly PluginPermission[] = []): Section {
  const sorted = sortPermissions(ps);
  return {
    title: k("plug.perms"),
    count: sorted.length,
    blocks: sorted.length
      ? sorted.map((p): Block => ({ sig: added.includes(p) ? Level.Action : WEIGHTY.has(p) ? Level.Warning : Level.Unknown, title: permissionWord(p), ...(added.includes(p) ? { sub: k("plug.perm.added") } : {}) }))
      : [{ para: k("plug.perm.none") }],
  };
}

const lead = (icon: string) => ({ tile: LeadTile.Icon as const, icon, hue: Hue.Cyan });
const home = [SETTINGS_ID, PLUGINS_PAGE];

export function installedDoc(p: InstalledPlugin): DocSpec {
  const state = pluginState(p);
  return {
    hero: {
      lead: lead(p.icon),
      title: raw(p.title),
      place: home,
      what: k(p.origin === PluginOrigin.Builtin ? "plug.what.builtin" : "plug.what.external", { version: p.version }),
      state,
      primary: p.enabled ? { icon: "close", label: k("plug.verb.disable"), act: { verb: PluginVerb.Disable } } : { icon: "check", label: k("plug.verb.enable"), act: { verb: PluginVerb.Enable } },
      ...(p.origin === PluginOrigin.External ? { more: [{ icon: "trash", label: k("plug.verb.uninstall"), act: { verb: PluginVerb.Uninstall } }] } : {}),
    },
    sections: [
      permissions(p.permissions, p.added),
      {
        title: k("plug.about"),
        blocks: [
          { para: p.description },
          { field: k("plug.version"), value: raw(p.version), mono: true },
          { field: k("plug.origin"), value: k(p.origin === PluginOrigin.Builtin ? "plug.origin.builtin" : "plug.origin.external") },
          ...(p.unverified ? [{ sig: Level.Warning, title: k("plug.unverified"), sub: k("plug.unverifiedSub") } satisfies Block] : []),
        ],
      },
    ],
    note: k(p.origin === PluginOrigin.Builtin ? "plug.note.builtin" : "plug.note.external"),
  };
}

export function offerDoc(o: PluginOffer): DocSpec {
  const can = o.revoked === null && o.trusted !== false && (!o.installed || o.update);
  const primary = o.revoked !== null ? undefined : o.trusted === false ? { icon: "shield", label: k("plug.verb.trust"), act: { verb: PluginVerb.Trust } } : can ? { icon: "plus", label: k(o.update ? "plug.verb.update" : "plug.verb.install"), act: { verb: PluginVerb.Install } } : undefined;
  return {
    hero: {
      lead: lead(o.icon),
      title: raw(o.title),
      place: home,
      what: k("plug.offer.what", { version: o.version, size: humanSize(o.size), source: hostOf(o.source) }),
      state: offerState(o),
      ...(primary ? { primary } : {}),
    },
    sections: [
      permissions(o.permissions),
      {
        title: k("plug.publisher"),
        blocks: [
          { field: k("plug.publisher"), value: o.publisher ? raw(o.publisher) : k("plug.unsigned"), mono: !!o.publisher, mark: o.signed ? { level: Level.Healthy, text: k("plug.signed") } : { level: Level.Warning, text: k("plug.unsigned") } },
          ...(o.fingerprint.length ? [{ field: k("plug.fingerprint"), value: raw(o.fingerprint.join(" ")), mono: true } satisfies Block] : []),
          { field: k("plug.source"), value: raw(o.source), mono: true },
          ...(o.homepage ? [{ field: k("plug.homepage"), value: raw(o.homepage), mono: true } satisfies Block] : []),
        ],
      },
      { title: k("plug.about"), blocks: [{ para: raw(o.description) }] },
    ],
  };
}

/// What the catalogue offers beyond what stands installed and current.
export const offered = (a: PluginAdmin): PluginOffer[] => (a.offers ?? []).filter((o) => !o.installed || o.update || o.revoked !== null);

/// The page's rows: what is installed, then what is offered.
export function pluginsKids(a: PluginAdmin): Entry[] {
  const offers = offered(a);
  return [
    { heading: k("plug.installed"), count: a.installed.length },
    ...a.installed.map((p) => ({ id: installedId(p.id) })),
    ...(offers.length ? [{ heading: k("plug.catalog"), count: offers.length }, ...offers.map((o) => ({ id: offerId(o) }))] : []),
  ];
}

export function pluginsDoc(a: PluginAdmin): DocSpec {
  const offers = offered(a);
  const catalog: Block[] =
    a.offers === null
      ? [{ skeleton: SkeletonKind.Fields, rows: 2, words: k("plug.reading") }]
      : offers.length
        ? offers.map((o): Block => ({ ref: offerId(o), lead: { tile: LeadTile.Plain, icon: o.icon }, title: raw(o.title), context: raw(`${o.version} · ${hostOf(o.source)}`), mark: offerState(o) }))
        : [{ para: k(a.offers.length ? "plug.catalogAllIn" : "plug.catalogEmpty") }];
  return {
    hero: {
      lead: { tile: LeadTile.Icon, icon: "grid", hue: Hue.Cyan },
      title: k("set.page.plugins"),
      place: [SETTINGS_ID],
      what: k("set.page.pluginsSub"),
      primary: { icon: "plus", label: k("plug.verb.installFile"), act: { verb: PluginVerb.InstallFile } },
      more: [
        { icon: "ext", label: k("plug.verb.installAddress"), act: { verb: PluginVerb.InstallAddress } },
        { icon: "refresh", label: k("plug.verb.refresh"), act: { verb: PluginVerb.Refresh } },
      ],
    },
    sections: [
      {
        title: k("plug.installed"),
        count: a.installed.length,
        blocks: a.installed.map((p): Block => ({ ref: installedId(p.id), lead: { tile: LeadTile.Plain, icon: p.icon }, title: raw(p.title), context: raw(p.version), mark: pluginState(p) })),
      },
      { title: k("plug.catalog"), ...(a.offers ? { count: offers.length } : {}), blocks: [...(a.stale ? [{ sig: Level.Warning, title: k("plug.stale"), sub: k("plug.staleSub") } satisfies Block] : []), ...catalog] },
      {
        title: k("plug.sources"),
        ...(a.sources ? { count: a.sources.length } : {}),
        aside: { label: k("plug.verb.addSource"), act: { verb: PluginVerb.AddSource }, icon: "plus" },
        blocks:
          a.sources === null
            ? [{ skeleton: SkeletonKind.Fields, rows: 1 }]
            : a.sources.length
              ? a.sources.map((s): Block => ({ field: raw(hostOf(s)), value: raw(s), mono: true }))
              : [{ para: k("plug.sourcesNone") }],
      },
    ],
    note: k("plug.note.page"),
  };
}
