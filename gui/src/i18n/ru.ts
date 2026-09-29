/// The Russian dictionary. It is also the source of keys: every other language
/// is obliged to cover exactly this set, or TypeScript will not build.
///
/// The core's words live in `i18n/ru.json` at the root of the repository, next
/// to the other languages and away from any code. The daemon reads the same
/// file: a Touch ID prompt and a notification are shown by the system, not by
/// the window, and there is no second place for them to be written down.
///
/// A plugin's words live with the plugin, in `crates/plugins/<id>/i18n/`, and
/// are merged in here. The core's dictionary knows nothing about a vault's
/// engines or an ssh route, and it has no business knowing.
import core from "../../../i18n/ru.json";
import hashicorp from "@plugin/hashicorp/i18n/ru.json";
import ssh from "@plugin/ssh/i18n/ru.json";
import vaultwarden from "@plugin/vaultwarden/i18n/ru.json";

export const ru = { ...core, ...hashicorp, ...ssh, ...vaultwarden };

export type Key = keyof typeof ru;
