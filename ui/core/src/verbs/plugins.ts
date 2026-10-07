// The verbs that manage plugins, under Settings › Plugins: turning one on is
// the consent to what it asks (its preview lists it, what an update added
// marked, a package past the catalogue said plainly), turning it off, removing
// it, installing from the catalogue, by an address or from a package on disk,
// trusting a publisher by the five words of its key, and the catalogue's
// sources. Each is a preview first; ↵ asks the backend. Pure.
import type { Key, Text } from "../i18n";
import { Level } from "../model/types";
import { type Directory, type Node, NodeKind } from "../path/directory";
import type { Verb } from "../path/query";
import { PluginAdminOp, PluginOrigin, type PluginAdminWrite, sortPermissions, validSource, WEIGHTY } from "../plugin/admin";
import { installedId, offerId, PLUGINS_PAGE, PluginVerb, permissionWord } from "../settings/plugins";
import { type Line, type Preview, PreviewKind } from "./spec";

const k = (key: Key, args?: Record<string, string | number | Text>): Text => (args ? { key, args } : { key });
const raw = (s: string): Text => ({ raw: s });

const onPage = (n: Node | null) => n?.id === PLUGINS_PAGE;
const installed = (n: Node | null) => (n?.kind === NodeKind.InstalledPlugin ? n.plugin! : null);
const offer = (n: Node | null) => (n?.kind === NodeKind.PluginOffer ? n.offer! : null);

function ready(target: string, p: Omit<Extract<Preview, { kind: PreviewKind.Ready }>, "kind" | "target" | "effect">, w: PluginAdminWrite): Preview {
  return { kind: PreviewKind.Ready, target, ...p, effect: { plugins: w } };
}

/// The first node of a kind a verb could be shown on, for its example.
const first = (dir: Directory, ok: (n: Node) => boolean) => dir.all().find(ok)?.id ?? null;

function enable(dir: Directory, obj: string): Preview {
  const p = installed(dir.node(obj))!;
  const ps = sortPermissions(p.permissions);
  const now: Line[] = [
    ...(p.unverified ? [{ level: Level.Warning, title: k("plug.consent.unverified"), sub: k("plug.consent.unverifiedSub") }] : []),
    ...(p.added.length ? [{ level: Level.Action, title: k("plug.consent.added", { n: p.added.length }), sub: k("plug.consent.addedSub") }] : []),
  ];
  return ready(
    obj,
    {
      title: k("plug.consent.title", { name: p.title }),
      lede: k("plug.consent.lede", { name: p.title, version: p.version }),
      steps: ps.length
        ? ps.map((x) => ({ title: permissionWord(x), sub: k(p.added.includes(x) ? "plug.perm.added" : WEIGHTY.has(x) ? "plug.perm.weighty" : "plug.perm.plain") }))
        : [{ title: k("plug.perm.none"), sub: k("plug.perm.noneSub") }],
      ...(now.length ? { now } : {}),
      stays: [{ level: Level.Healthy, title: k("plug.consent.stays"), sub: k("plug.consent.staysSub") }],
      go: k("plug.verb.enable"),
      note: k("plug.consent.note"),
    },
    { op: PluginAdminOp.Enable, id: p.id },
  );
}

function disable(dir: Directory, obj: string): Preview {
  const p = installed(dir.node(obj))!;
  return ready(
    obj,
    {
      title: k("plug.off.title", { name: p.title }),
      lede: k("plug.off.lede"),
      steps: [{ title: k("plug.off.s1"), sub: k("plug.off.s1sub") }],
      stays: [{ level: Level.Healthy, title: k("plug.off.stays"), sub: k("plug.off.staysSub") }],
      go: k("plug.verb.disable"),
      note: k("verb.reversible"),
    },
    { op: PluginAdminOp.Disable, id: p.id },
  );
}

function uninstall(dir: Directory, obj: string): Preview {
  const p = installed(dir.node(obj))!;
  return ready(
    obj,
    {
      title: k("plug.remove.title", { name: p.title }),
      lede: k("plug.remove.lede", { name: p.title }),
      steps: [
        { title: k("plug.remove.s1"), sub: k("plug.remove.s1sub") },
        { title: k("plug.remove.s2"), sub: k("plug.remove.s2sub") },
      ],
      stays: [{ level: Level.Healthy, title: k("plug.remove.stays"), sub: k("plug.remove.staysSub") }],
      go: k("plug.verb.uninstall"),
      danger: true,
    },
    { op: PluginAdminOp.Remove, id: p.id },
  );
}

function install(dir: Directory, obj: string): Preview {
  const o = offer(dir.node(obj))!;
  return ready(
    obj,
    {
      title: k(o.update ? "plug.install.updateTitle" : "plug.install.title", { name: o.title, version: o.version }),
      lede: k("plug.install.lede"),
      steps: [
        { title: k("plug.install.s1"), sub: k(o.signed ? "plug.install.s1signed" : "plug.install.s1unsigned") },
        { title: k("plug.install.s2"), sub: k("plug.install.s2sub") },
        { title: k("plug.install.s3"), sub: k("plug.install.s3sub") },
      ],
      ...(o.signed ? {} : { now: [{ level: Level.Warning, title: k("plug.unsigned"), sub: k("plug.consent.unverifiedSub") }] }),
      go: k(o.update ? "plug.verb.update" : "plug.verb.install"),
    },
    { op: PluginAdminOp.Install, from: o.from },
  );
}

function trust(dir: Directory, obj: string): Preview {
  const o = offer(dir.node(obj))!;
  const publisher = o.publisher!;
  return ready(
    obj,
    {
      title: k("plug.trust.title", { name: publisher }),
      lede: k("plug.trust.lede", { name: publisher, plugin: o.title }),
      steps: [
        { title: o.fingerprint.length ? raw(o.fingerprint.join(" ")) : k("plug.trust.noFingerprint"), sub: k("plug.trust.compare") },
        { title: k("plug.trust.s2"), sub: k("plug.trust.s2sub") },
      ],
      go: k("plug.verb.trust"),
      ...(o.fingerprint.length ? {} : { blocked: k("plug.trust.noFingerprint") }),
    },
    { op: PluginAdminOp.Trust, publisher },
  );
}

/// The two pickers are different windows: which one opens is the line's.
enum Package {
  Archive = "archive",
  Folder = "folder",
}

function installFile(_dir: Directory, obj: string, arg: string): Preview {
  const folder = arg.trim() === Package.Folder;
  return ready(
    obj,
    {
      title: k("plug.verb.installFile"),
      lede: k("plug.file.lede"),
      form: [
        {
          inputs: [
            {
              id: "package",
              label: k("plug.file.what"),
              choices: [
                { label: k("plug.file.archive"), arg: Package.Archive, on: !folder },
                { label: k("plug.file.folder"), arg: Package.Folder, on: folder },
              ],
            },
          ],
        },
      ],
      steps: [
        { title: k("plug.file.s1"), sub: k(folder ? "plug.file.s1folder" : "plug.file.s1archive") },
        { title: k("plug.install.s2"), sub: k("plug.install.s2sub") },
        { title: k("plug.install.s3"), sub: k("plug.install.s3sub") },
      ],
      now: [{ level: Level.Warning, title: k("plug.unsigned"), sub: k("plug.consent.unverifiedSub") }],
      go: k("plug.file.go"),
    },
    { op: PluginAdminOp.InstallFile, archive: !folder },
  );
}

function installAddress(_dir: Directory, obj: string, arg: string): Preview {
  const url = arg.trim();
  const blocked = !url ? k("plug.address.need") : !validSource(url) ? k("plug.address.bad") : undefined;
  return ready(
    obj,
    {
      title: k("plug.verb.installAddress"),
      lede: k("plug.address.lede"),
      form: [{ inputs: [{ id: "url", label: k("plug.address.label"), text: arg, placeholder: raw("https://…/plugin-1.0.0.tar.gz"), mono: true, with: (v) => v }] }],
      steps: [
        { title: k("plug.address.s1"), sub: raw(url || "—") },
        { title: k("plug.install.s2"), sub: k("plug.install.s2sub") },
        { title: k("plug.install.s3"), sub: k("plug.install.s3sub") },
      ],
      now: [{ level: Level.Warning, title: k("plug.unsigned"), sub: k("plug.consent.unverifiedSub") }],
      go: k("plug.verb.install"),
      ...(blocked ? { blocked } : {}),
    },
    { op: PluginAdminOp.Install, from: url },
  );
}

function addSource(dir: Directory, obj: string, arg: string): Preview {
  const url = arg.trim();
  const now = dir.plugins?.sources ?? null;
  const blocked = now === null ? k("plug.reading") : !url ? k("plug.address.need") : !validSource(url) ? k("plug.address.bad") : now.includes(url) ? k("plug.source.dupe") : undefined;
  return ready(
    obj,
    {
      title: k("plug.verb.addSource"),
      lede: k("plug.source.lede"),
      form: [{ inputs: [{ id: "url", label: k("plug.address.label"), text: arg, placeholder: raw("https://…/index.json"), mono: true, with: (v) => v }] }],
      steps: [{ title: k("plug.source.s1"), sub: raw(url || "—") }],
      stays: [{ level: Level.Healthy, title: k("plug.source.stays"), sub: k("plug.source.staysSub") }],
      go: k("plug.verb.addSource"),
      ...(blocked ? { blocked } : {}),
    },
    { op: PluginAdminOp.Sources, set: [...(now ?? []), url] },
  );
}

function removeSource(dir: Directory, obj: string, arg: string): Preview {
  const now = dir.plugins?.sources ?? [];
  const pick = now.includes(arg.trim()) ? arg.trim() : null;
  return ready(
    obj,
    {
      title: k("plug.verb.removeSource"),
      lede: k("plug.source.removeLede"),
      form: [{ inputs: [{ id: "source", label: k("plug.sources"), choices: now.map((s) => ({ label: raw(s), arg: s, on: s === pick })) }] }],
      steps: [{ title: k("plug.source.r1"), sub: k("plug.source.r1sub") }],
      stays: [{ level: Level.Healthy, title: k("plug.source.removeStays"), sub: k("plug.source.removeStaysSub") }],
      go: k("plug.verb.removeSource"),
      danger: true,
      ...(pick ? {} : { blocked: k("plug.source.pick") }),
    },
    { op: PluginAdminOp.Sources, set: now.filter((s) => s !== pick) },
  );
}

function refresh(_dir: Directory, obj: string): Preview {
  return ready(
    obj,
    {
      title: k("plug.verb.refresh"),
      lede: k("plug.refresh.lede"),
      steps: [{ title: k("plug.refresh.s1"), sub: k("plug.refresh.s1sub") }],
      stays: [{ level: Level.Healthy, title: k("plug.refresh.stays"), sub: k("plug.refresh.staysSub") }],
      go: k("plug.verb.refresh"),
    },
    { op: PluginAdminOp.Refresh },
  );
}

const offOne = (n: Node | null) => installed(n)?.enabled === false;
const onOne = (n: Node | null) => installed(n)?.enabled === true;
const removable = (n: Node | null) => installed(n)?.origin === PluginOrigin.External;
const installable = (n: Node | null) => {
  const o = offer(n);
  return !!o && o.revoked === null && o.trusted !== false && (!o.installed || o.update);
};
const untrusted = (n: Node | null) => {
  const o = offer(n);
  return !!o && o.trusted === false && !!o.publisher;
};
const withSources = (n: Node | null) => onPage(n);

export const PLUGIN_VERBS: Verb[] = [
  { id: PluginVerb.Enable, name: k("plug.verb.enable"), icon: "check", applies: offOne, preview: enable, example: (dir) => first(dir, offOne) },
  { id: PluginVerb.Disable, name: k("plug.verb.disable"), icon: "close", applies: onOne, preview: disable, example: (dir) => first(dir, onOne) },
  { id: PluginVerb.Uninstall, name: k("plug.verb.uninstall"), icon: "trash", applies: removable, preview: uninstall, example: (dir) => first(dir, removable) },
  { id: PluginVerb.Install, name: k("plug.verb.install"), icon: "plus", applies: installable, preview: install, example: (dir) => first(dir, installable) },
  { id: PluginVerb.Trust, name: k("plug.verb.trust"), icon: "shield", applies: untrusted, preview: trust, example: (dir) => first(dir, untrusted) },
  { id: PluginVerb.InstallFile, name: k("plug.verb.installFile"), icon: "plus", applies: onPage, preview: installFile, example: () => PLUGINS_PAGE },
  { id: PluginVerb.InstallAddress, name: k("plug.verb.installAddress"), icon: "ext", applies: onPage, preview: installAddress, example: () => PLUGINS_PAGE },
  { id: PluginVerb.AddSource, name: k("plug.verb.addSource"), icon: "plus", applies: withSources, preview: addSource, example: () => PLUGINS_PAGE },
  { id: PluginVerb.RemoveSource, name: k("plug.verb.removeSource"), icon: "trash", applies: (n) => onPage(n), preview: removeSource, example: () => PLUGINS_PAGE },
  { id: PluginVerb.Refresh, name: k("plug.verb.refresh"), icon: "refresh", applies: onPage, preview: refresh, example: () => PLUGINS_PAGE },
];

/// Where an installed plugin's page is, to go to after it was installed.
export { installedId, offerId };
