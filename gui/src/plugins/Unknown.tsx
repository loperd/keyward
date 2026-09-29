import { Empty } from "../ui";
import { t } from "../i18n";
import type { PluginScreenProps } from "./index";

/// The daemon has a plugin the interface does not: different versions were
/// built. An empty state rather than a crash — the section simply says what is
/// missing.
export function UnknownPlugin({ manifest }: PluginScreenProps) {
  return (
    <Empty
      icon="warn"
      title={t("plugin.unknown.title", { id: manifest.id })}
      body={t("plugin.unknown.body")}
    />
  );
}
