import { has, t, locale, type Key } from "../i18n";
import type { Text } from "./types";

/// A declared word in the person's language: a key of the plugin's
/// dictionary with its arguments, or a value as it is.
export function tx(v?: Text | null): string {
  if (!v) return "";
  if ("raw" in v) return v.raw;
  // A word the dictionaries lack is the plugin's mistake: said loudly, and
  // the key is shown in its place rather than the screen torn down.
  if (!has(v.key)) {
    console.error(`keyward: no word for ${v.key}`);
    return v.key;
  }
  return t(v.key as Key, v.args as Record<string, string | number> | undefined);
}

/// "5 minutes ago", in the person's language.
export function ago(seconds?: number | null): string {
  if (!seconds) return "";
  const diff = Math.round(seconds - Date.now() / 1000);
  const fmt = new Intl.RelativeTimeFormat(locale(), { numeric: "auto" });
  const abs = Math.abs(diff);
  if (abs < 60) return fmt.format(diff, "second");
  if (abs < 3600) return fmt.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return fmt.format(Math.round(diff / 3600), "hour");
  return fmt.format(Math.round(diff / 86400), "day");
}
