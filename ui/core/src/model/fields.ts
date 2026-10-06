// What a field's key means beyond a caption: the two kinds of custom field
// whose meaning is not in their text, and a site's address read for showing.
// Both backends send these as the daemon does: `checkbox` for a yes/no field
// and `link:<n>` (or `link:none`) for a field that points at another one, with
// the person's own name as the label.
import type { Key, Text } from "../i18n";
import type { Field } from "./types";

/// Bitwarden's numbers for the fields a linked field can point at.
const LINK_TARGETS: Record<number, string> = {
  100: "username",
  101: "password",
  300: "cardholderName",
  301: "expMonth",
  302: "expYear",
  303: "code",
  304: "brand",
  305: "number",
  400: "title",
  401: "middleName",
  402: "address1",
  403: "address2",
  404: "address3",
  405: "city",
  406: "state",
  407: "postalCode",
  408: "country",
  409: "company",
  410: "email",
  411: "phone",
  412: "ssn",
  413: "username",
  414: "passportNumber",
  415: "licenseNumber",
  416: "firstName",
  417: "lastName",
  418: "fullName",
};

/// A custom field: its caption is what a person named it.
export const isCustomKind = (key: string | null): boolean => key === "checkbox" || (key?.startsWith("link:") ?? false);

/// The words a checkbox or a linked field shows instead of its raw value.
export function customValue(f: Field): Text | null {
  if (f.key === "checkbox") {
    if (f.value !== "true" && f.value !== "false") throw new Error(`a checkbox field holds "${f.value}", not true or false`);
    return { key: f.value === "true" ? "value.yes" : "value.no" };
  }
  if (f.key?.startsWith("link:")) {
    const at = f.key.slice(5);
    if (at === "none") return { key: "link.none" };
    const n = Number(at);
    const target = Number.isInteger(n) ? LINK_TARGETS[n] : undefined;
    // A number newer than this window is shown as it is, not guessed at.
    return { key: "field.linkedTo", args: { field: target ? { key: `link.${target}` as Key } : { raw: `#${at}` } } };
  }
  return null;
}

/// A site's host for showing. A Bitwarden URI is free text: often without a
/// scheme ("example.com"), sometimes an app id or a pattern. Without a
/// scheme it is read as https; what still is not an address has no host and
/// is shown as it was written.
export function siteHost(uri: string): string | null {
  for (const candidate of /^[a-z][a-z0-9+.-]*:/i.test(uri) ? [uri] : [`https://${uri}`]) {
    try {
      const host = new URL(candidate).host;
      if (host) return host;
    } catch {
      // Not an address: the caller shows the text itself.
    }
  }
  return null;
}
