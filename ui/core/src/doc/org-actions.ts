// What an organisation's pages offer: the verbs of `verbs/org.ts`, only where
// they would run (the organisation's `can`, and never on yourself where it
// would lock you out). A page asks here instead of deciding itself, so a
// button and the line never disagree about what may be done. Pure.
import type { Key, Text } from "../i18n";
import type { Directory, Node } from "../path/directory";
import { ORG_VERBS, verbLine } from "../verbs/org";
import type { Act, Action } from "./spec";

const k = (key: Key): Text => ({ key });
const verb = (icon: string, label: Key, v: string): Action => ({ icon, label: k(label), act: { verb: v } });

/// Whether an organisation verb runs on a node.
export function fits(id: string, n: Node | null): boolean {
  const v = ORG_VERBS.find((x) => x.id === id);
  if (!v) throw new Error(`no organisation verb "${id}"`);
  return v.applies(n);
}

/// A member's page: confirming first while they wait for it, then their role
/// and access, then removing them.
export function memberActions(n: Node): { primary?: Action; more: Action[] } {
  const confirm = fits("confirm", n) ? verb("check", "doc.confirm", "confirm") : null;
  const role = fits("role", n) ? verb("people", "verb.org.role", "role") : null;
  const remove = fits("remove", n) ? verb("trash", "verb.org.remove", "remove") : null;
  const primary = confirm ?? role;
  return { ...(primary ? { primary } : {}), more: [...(confirm && role ? [role] : []), ...(remove ? [remove] : [])] };
}

/// A collection's page: renaming and deleting it.
export function collectionActions(n: Node): Action[] {
  return [...(fits("rename", n) ? [verb("edit", "verb.org.rename", "rename")] : []), ...(fits("delete", n) ? [verb("trash", "verb.org.delete", "delete")] : [])];
}

/// A new collection, where one may be made.
export const newCollection = (n: Node): Action | null => (fits("new collection", n) ? verb("stack", "doc.newCollection", "new collection") : null);
/// An invite, where one may be sent.
export const invite = (n: Node): Action | null => (fits("invite", n) ? verb("mail", "doc.invite", "invite") : null);

/// A row's way to a verb on another node: the line that goes there and
/// opens it, or a step to the node where the verb would not run.
export function verbOn(dir: Directory, id: string, v: string, arg = ""): Act {
  return fits(v, dir.node(id)) ? { run: verbLine(dir, id, v, arg) } : { go: id };
}
