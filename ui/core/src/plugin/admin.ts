// The plugins installed here and those on offer, as the window manages them:
// what each asks of the core, whether it is on, where it came from, and the
// catalogue's sources. The desktop app reads them from the daemon and parses
// them at its boundary into these; the web app has no plugins. Pure.
import type { Text, Words } from "../i18n";
import { enumParser } from "../model/enum";

/// Where a plugin came from: built in (switched off, never removed) or
/// installed from a package.
export enum PluginOrigin {
  Builtin = "builtin",
  External = "external",
}
export const parsePluginOrigin = enumParser(PluginOrigin, "a plugin's origin");

/// What a plugin asks of the core (keyward-plugin's `Permission`).
export enum PluginPermission {
  Entries = "entries",
  Items = "items",
  ItemsWrite = "items_write",
  Notices = "notices",
  Clipboard = "clipboard",
  SshSign = "ssh_sign",
  Secrets = "secrets",
  Keychain = "keychain",
  Network = "network",
}
export const parsePluginPermission = enumParser(PluginPermission, "a plugin's permission");

/// The order the permissions are read in: the most peaceable first, so that
/// "read passwords" lands in the same place every time.
export const PERMISSION_ORDER: PluginPermission[] = Object.values(PluginPermission);
/// What, together, could carry the vault away: said in their colour.
export const WEIGHTY: ReadonlySet<PluginPermission> = new Set([PluginPermission.Secrets, PluginPermission.Network, PluginPermission.Keychain, PluginPermission.SshSign]);
export const sortPermissions = (ps: readonly PluginPermission[]) => PERMISSION_ORDER.filter((p) => ps.includes(p));

export type InstalledPlugin = {
  id: string;
  title: string;
  /// One of the window's icons.
  icon: string;
  version: string;
  /// What it is for, in the plugin's words where it has them.
  description: Text;
  origin: PluginOrigin;
  enabled: boolean;
  permissions: PluginPermission[];
  /// Installed past the catalogue: no signature, nothing to compare.
  unverified: boolean;
  /// What an update asks for beyond what was agreed to; the daemon keeps
  /// it off until it is.
  added: PluginPermission[];
  /// Its version was withdrawn by the catalogue, and why.
  revoked: string | null;
  /// Its dictionary, registered under its id while the session lasts.
  words?: Words;
};

/// Something a catalogue offers.
export type PluginOffer = {
  id: string;
  title: string;
  icon: string;
  description: string;
  homepage: string;
  /// The catalogue it came from.
  source: string;
  /// What the daemon installs it from: the package's address, or its id.
  from: string;
  version: string;
  permissions: PluginPermission[];
  /// Bytes.
  size: number;
  installed: boolean;
  installedVersion: string | null;
  update: boolean;
  publisher: string | null;
  signed: boolean;
  /// `false`: its publisher's key is to be confirmed first; `null`: the
  /// catalogue says nothing of trust.
  trusted: boolean | null;
  /// The publisher key's fingerprint, five words.
  fingerprint: string[];
  revoked: string | null;
};

/// What the window knows of plugins: the installed ones always (they come
/// with the places), the catalogue and its sources once asked (`null` till
/// then). `stale`: the catalogue answered from its cache.
export type PluginAdmin = { installed: InstalledPlugin[]; offers: PluginOffer[] | null; stale: boolean; sources: string[] | null };

export enum PluginAdminOp {
  Enable = "enable",
  Disable = "disable",
  Remove = "remove",
  /// From an offer, or an address typed in.
  Install = "install",
  /// From a package on disk the person picks: an archive or a folder.
  InstallFile = "installFile",
  Trust = "trust",
  Sources = "sources",
  /// The catalogue read again from the network.
  Refresh = "refresh",
}
export type PluginAdminWrite =
  | { op: PluginAdminOp.Enable | PluginAdminOp.Disable | PluginAdminOp.Remove; id: string }
  | { op: PluginAdminOp.Install; from: string }
  | { op: PluginAdminOp.InstallFile; archive: boolean }
  | { op: PluginAdminOp.Trust; publisher: string }
  | { op: PluginAdminOp.Sources; set: string[] }
  | { op: PluginAdminOp.Refresh };

/// An address of a catalogue or a package the daemon takes: https, or
/// file for one's own build.
export const validSource = (url: string) => /^(https|file):\/\/\S+$/.test(url.trim());

/// A size the way a person reads it.
export function humanSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/// A catalogue's host, for a quiet line; a file's address as it is.
export const hostOf = (url: string): string => new URL(url).host || url;
