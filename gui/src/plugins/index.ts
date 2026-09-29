import { UnknownPlugin } from "./Unknown";
import type { PluginEntry } from "./types";
import { HashicorpScreen } from "@plugin/hashicorp/ui/Screen";
import { HashicorpContext } from "@plugin/hashicorp/ui/Context";
import { HashicorpSettings } from "@plugin/hashicorp/ui/Settings";
import { SshScreen } from "@plugin/ssh/ui/Screen";
import { SshSettings } from "@plugin/ssh/ui/Settings";
import { SshItemCard } from "@plugin/ssh/ui/ItemCard";
import { SshKeyEditor } from "@plugin/ssh/ui/KeyEditor";
import { VaultwardenScreen } from "@plugin/vaultwarden/ui/Screen";
import type { Manifest, PluginItemEditor } from "./types";

export type { PluginScreenProps, PluginEntry } from "./types";

/// The only place in the core that knows a plugin by name.
///
/// The screens themselves live with their plugins — `crates/plugins/<id>/ui` —
/// together with the Rust that serves them and the words they say. What is left
/// here is the wiring: which section is drawn by whom. When a plugin's UI stops
/// being built into the window and travels inside its package instead, this
/// table is the one thing that has to go.
const REGISTRY: Record<string, PluginEntry> = {
  hashicorp: { Screen: HashicorpScreen, Context: HashicorpContext, SettingsSection: HashicorpSettings },
  ssh: {
    Screen: SshScreen,
    SettingsSection: SshSettings,
    ItemCard: SshItemCard,
    ItemEditor: { kind: "ssh_key", code: 5, Component: SshKeyEditor },
  },
  vaultwarden: { Screen: VaultwardenScreen },
};

/// The item editors of the plugins that are on: which kinds of items the form
/// can make beyond the core's own, and who draws their part of it. A plugin
/// that is off takes its kind with it — nobody would be left to fill it in.
export function itemEditors(plugins: Manifest[]): PluginItemEditor[] {
  return plugins
    .filter((m) => m.enabled)
    .map((m) => pluginEntry(m.id).ItemEditor)
    .filter((e): e is PluginItemEditor => Boolean(e));
}

/// A section by a plugin's name. An unfamiliar name is no reason to fall over:
/// the daemon may be newer than the interface.
export function pluginEntry(id: string): PluginEntry {
  return REGISTRY[id] ?? { Screen: UnknownPlugin };
}
