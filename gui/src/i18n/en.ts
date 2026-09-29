/// The English dictionary. Typed against the Russian one, so a forgotten key
/// is a compile error rather than a blank label at runtime. The core's words
/// live in `i18n/en.json` at the root of the repository, a plugin's in
/// `crates/plugins/<id>/i18n/en.json`.
import core from "../../../i18n/en.json";
import hashicorp from "@plugin/hashicorp/i18n/en.json";
import ssh from "@plugin/ssh/i18n/en.json";
import vaultwarden from "@plugin/vaultwarden/i18n/en.json";

import type { Key } from "./ru";

export const en: Record<Key, string> = { ...core, ...hashicorp, ...ssh, ...vaultwarden };
