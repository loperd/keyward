import type { ComponentType } from "react";
import type { Catalog, ItemDetail } from "../types";
import type { Manifest } from "../../app/plugins/types";

// The plugins' data types live with the new window (gui/app); what stays here
// is what the old window's plugin screens are made of.
export * from "../../app/plugins/types";

/// What the core gives a plugin's section. Nothing more is needed here: a
/// plugin fetches its own data itself, through `call`.
export type PluginScreenProps = {
  /// The card out of the `plugins()` answer.
  manifest: Manifest;
  /// The catalogue of items: a plugin sometimes needs the vault's notes.
  catalog: Catalog | null;
  loading: boolean;
  /// The items changed, so the shell should re-read the catalogue.
  onChanged: () => void;
  onCopied: (text: string) => void;
};

/// What a plugin gets when it draws a block on an item's card. The card hands
/// over the item and nothing else: whether there is anything of the plugin's on
/// it, the plugin decides by looking.
export type PluginItemCardProps = {
  detail: ItemDetail;
  entryId: string;
  onChanged: () => void;
};

/// What a plugin gets when it draws its part of the form for creating or
/// editing an item of a kind it owns.
///
/// The form stays the core's: the name, the folder, the note and the save
/// button are its own. The plugin's editor answers with a piece of the edit —
/// merged into what the form sends — and says whether that piece is ready;
/// while it is not, the form will not save.
export type PluginItemEditorProps = {
  /// The item being edited; `null` while a new one is being made.
  detail: ItemDetail | null;
  onChange: (patch: Record<string, unknown> | null, ready: boolean) => void;
  onCopied: (text: string) => void;
};

/// A plugin's editor for one kind of item.
export type PluginItemEditor = {
  /// The kind in the catalogue's terms: `ssh_key`.
  kind: string;
  /// The kind's number in Bitwarden's terms, which creating an item takes.
  code: number;
  Component: ComponentType<PluginItemEditorProps>;
};

export type PluginEntry = {
  /// The section's main column.
  Screen: ComponentType<PluginScreenProps>;
  /// The screen fills the whole working area itself, with no padding and no
  /// scroll of the shell's own: a terminal, say.
  flush?: boolean;
  /// The section's left column: not every one has it.
  Context?: ComponentType<PluginScreenProps>;
  /// A block in the settings. The heading comes from the plugin's caption.
  SettingsSection?: ComponentType;
  /// A block on an item's card: an ssh key's routes, a vault's connection.
  /// Drawn for every plugin that is on, and a plugin with nothing to say about
  /// this item draws nothing.
  ItemCard?: ComponentType<PluginItemCardProps>;
  /// The part of the item form for a kind the plugin owns: an ssh key's key.
  ItemEditor?: PluginItemEditor;
};
