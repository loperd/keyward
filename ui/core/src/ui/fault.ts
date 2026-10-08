// A backend's refusal in the person's words: the daemon says what went wrong
// as a dictionary key (`err.*`), sometimes with the values for its blanks; a
// message that is no key is shown as it came.
import { text } from "../i18n";
import { faultText } from "./gate-machine";

export function faultWords(e: unknown): string {
  const msg = (e instanceof Error ? e.message : String(e)).trim();
  const known = faultText(msg);
  return known ? text(known) : msg;
}
