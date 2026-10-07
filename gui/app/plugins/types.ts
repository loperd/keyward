
/// The plugins' types — a mirror of `crates/plugin/src/lib.rs`.
///
/// A file of its own rather than part of `call.ts`: a plugin's manifest is now
/// read by the rail, by the settings section and by the consent dialogue alike,
/// while `call.ts` is about the conversation with the daemon, not about what a
/// plugin is made of.

/// Where a plugin came from — `keyward_plugin::Origin`.
///
/// A built-in one is compiled together with the daemon: it can be switched off
/// but not deleted. An external one is a program of its own in
/// `~/.keyward/plugins/<id>`.
export type Origin = "builtin" | "external";

/// What a plugin asks of the core — `keyward_plugin::Permission`.
///
/// A request rather than a right: the daemon checks the permission on every
/// call, while the person sees the list once, at the installation.
export type Permission = "entries" | "secrets" | "items" | "items_write" | "notices" | "ssh_sign" | "network" | "keychain";

/// The order the permissions are shown in: from the most peaceable to the most
/// dangerous. A plugin lists them as it pleases, but the list always reads the
/// same way — otherwise "read passwords" lands somewhere new every time and
/// stops being noticed.
export const PERMISSION_ORDER: Permission[] = ["entries", "items", "items_write", "notices", "ssh_sign", "secrets", "keychain", "network"];

/// A plugin's manifest — `keyward_plugin::Manifest`.
export type Manifest = {
  /// The namespace in the protocol: `ssh`, `hashicorp`.
  id: string;
  /// The name, in case the interface has no translation.
  title: string;
  /// The name of an icon from the interface's set.
  icon: string;
  /// Show the section in the rail on the left.
  section: boolean;
  /// The section is needed only while the vault is open.
  needs_unlocked: boolean;
  /// The section applies only where the plugin says so: it is asked
  /// `available`, and the section shows on a yes.
  probe?: boolean;
  /// The screens are declared by the plugin and drawn by the window's own
  /// kit; the plugin ships no code for them.
  declared?: boolean;
  /// The plugin adds places to the new window's path, asked on the same
  /// sealed road as the declared screens.
  places?: boolean;
  /// The package's version; for the built-in ones, the application's.
  version: string;
  /// One line about what it is for.
  description: string;
  origin: Origin;
  /// A switched-off one is not listed in the sections, receives no events and
  /// answers no calls.
  enabled: boolean;
  /// What the plugin asks of the core.
  permissions: Permission[];
  /// The package was installed past the catalogue — from a directory on disk,
  /// from an archive or by an address typed in by hand: there is no signature
  /// and no sha256 to check against. The daemon puts this mark on itself, and
  /// the consent dialogue has to say so plainly.
  unverified?: boolean;
  /// An update asked for more than was installed. The daemon leaves a plugin
  /// like that switched off, and the interface has to show not the whole list
  /// again but exactly what was added.
  added_permissions?: Permission[];
  /// The version was withdrawn by the catalogue: the daemon switches the plugin
  /// off itself, and the card explains why.
  revoked_reason?: string;
};

/// A catalogue entry — something there is to install.
///
/// Not a `Manifest`: a manifest describes a plugin that already lies on disk,
/// while a catalogue entry is an offer. The fields about installation
/// (`installed`, `update`) the daemon works out itself, comparing the catalogue
/// with what is installed.
export type CatalogEntry = {
  id: string;
  title: string;
  description: string;
  /// The name of an icon from the interface's set; an unknown name is drawn as
  /// a placeholder.
  icon: string;
  /// The project's page — shown as a link, so that there is somewhere to look
  /// before installing.
  homepage: string;
  /// The address of the catalogue the entry came from: a person may have
  /// several, and is entitled to know whose plugin this is.
  source: string;
  /// The package's address. It is what the daemon is given at the
  /// installation; when the catalogue did not name one, the `id` remains — the
  /// daemon will find the package in its own copy of the catalogue.
  url?: string;
  /// The version on offer — the first one that suits the machine.
  version: string;
  permissions: Permission[];
  /// The package's size in bytes.
  size: number;
  installed: boolean;
  /// The version installed just now; empty when none is.
  installed_version?: string | null;
  /// The installed version is older than the one on offer.
  update: boolean;
  /// The entry comes from the cache: the catalogue is out of reach. Not an
  /// error — the list may simply not be fresh.
  stale?: boolean;
  /// Who published the package — the identifier of the publisher's key.
  publisher?: string;
  /// The package has a signature. Its absence is not "broken" but "installed as
  /// a developer's package", and the card says so.
  signed?: boolean;
  /// The publisher is in the list of trusted ones. `false` means it cannot be
  /// installed until the key is confirmed; `undefined` means the catalogue said
  /// nothing about trust, and there is nothing to stand in the way of the
  /// installation.
  trusted?: boolean;
  /// The publisher key's fingerprint in the same five words as an account's:
  /// five words can be compared, sixty-four characters cannot.
  fingerprint?: string[] | string;
  /// The version has been withdrawn: there is nothing to install, and the `reason`
  /// says why.
  revoked?: boolean;
  reason?: string;
};

/// A fingerprint on one line. The daemon gives out five words as a list (as it
/// does for an account), but a foreign catalogue may well send a ready-made
/// string.
export function fingerprintPhrase(value: string[] | string | undefined): string {
  if (!value) return "";
  return Array.isArray(value) ? value.join("-") : value;
}

/// An address of a catalogue the daemon will accept: `https://` is the ordinary
/// way, `file://` is for development. It is checked here so that a typo is
/// spoken of at once, without driving a request into the daemon.
export function validSource(url: string): boolean {
  const trimmed = url.trim();
  return trimmed.startsWith("https://") || trimmed.startsWith("file://");
}

/// The permissions in an order that makes sense, with no unfamiliar names in
/// the middle of the list: whatever the interface does not know goes to the
/// tail as it is.
export function sortPermissions(permissions: Permission[]): Permission[] {
  const known = PERMISSION_ORDER.filter((p) => permissions.includes(p));
  const rest = permissions.filter((p) => !PERMISSION_ORDER.includes(p));
  return [...known, ...rest];
}
