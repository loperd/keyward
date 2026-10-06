// The terminal's sealed link: the window's, pointed at this plugin's
// operations.
import { openLink as open, type Link } from "@keyward/plugins/link";

export { Refused, unb64, bytesToB64, type Link, type LaneName } from "@keyward/plugins/link";

/// Makes a link with the ssh plugin: one per terminal tab.
export function openLink(): Promise<Link> {
  return open({ plugin: "ssh", link: "term_link", call: "term" });
}
