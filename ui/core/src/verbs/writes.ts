// The verbs that change a vault's items and folders: `> edit` opens the
// item's own document for editing, `> new` (and `> new login|card|note|
// identity|ssh`) opens a new item's document in the place the line stands
// in, and `> new folder`, `> rename`, `> delete` change folders through a
// preview. They are offered only where the app gives the window its writes.
// Pure.
import type { Key, Text } from "../i18n";
import { type Directory, type Node, NodeKind } from "../path/directory";
import type { Verb } from "../path/query";
import type { Writes } from "../writes";
import { type Delta, type FolderWrite, type Preview, PreviewKind, FolderOp } from "./spec";
import { LeadTile, type Lead } from "../doc/spec";
import { ItemKind, Level } from "../model/types";

const k = (key: Key, args?: Record<string, string | number | Text>): Text => (args ? { key, args } : { key });
const raw = (s: string): Text => ({ raw: s });
const FOLDER_LEAD: Lead = { tile: LeadTile.Plain, icon: "folder" };

/// An item one may change: in the vault, not in the trash.
const editable = (n: Node | null) => !!n?.item && !n.item.deleted;
/// A place a new item can be made in.
export function makesItems(n: Node | null): boolean {
  if (!n) return true;
  if (n.item) return !n.item.deleted;
  if ([NodeKind.Root, NodeKind.All, NodeKind.Personal, NodeKind.Folder, NodeKind.Org, NodeKind.Collection].includes(n.kind)) return true;
  return n.kind === NodeKind.Section && n.home[0]?.startsWith("org:") === true;
}
/// Folders are personal: made where the personal vault is.
const makesFolders = (n: Node | null) => !n || [NodeKind.Root, NodeKind.All, NodeKind.Personal, NodeKind.Folder].includes(n.kind);
const isFolder = (n: Node | null) => n?.kind === NodeKind.Folder;
const folderId = (n: Node) => n.id.slice("folder:".length);
const firstFolder = (dir: Directory) => dir.all().find((n) => n.kind === NodeKind.Folder)?.id ?? null;
const firstItem = (dir: Directory) => dir.all().find((n) => editable(n))?.id ?? null;

const taken = (dir: Directory, name: string, except?: string) => dir.catalog.folders.some((f) => f.id !== except && f.name.trim().toLowerCase() === name.trim().toLowerCase());

function newFolder(dir: Directory, _obj: string, arg: string): Preview {
  const name = arg.trim();
  const blocked = !name ? k("verb.folder.needName") : taken(dir, name) ? k("verb.folder.taken", { name }) : undefined;
  return {
    kind: PreviewKind.Ready,
    target: "personal",
    title: name ? k("verb.folder.newNamed", { name }) : k("doc.newFolder"),
    lede: k("verb.folder.newLede"),
    form: [{ inputs: [{ id: "name", label: k("verb.folder.name"), text: arg, placeholder: k("verb.folder.nameHint"), with: (v) => v }] }],
    steps: [],
    changes: { rows: [{ lead: FOLDER_LEAD, name: name ? raw(name) : k("verb.folder.unnamed"), from: { faint: k("verb.folder.none") }, to: { level: Level.Healthy, text: k("verb.folder.empty") } }] },
    stays: [{ level: Level.Healthy, title: k("verb.folder.onlyYou"), sub: k("verb.folder.onlyYouSub") }],
    go: k("verb.folder.newGo"),
    effect: { folder: { op: FolderOp.Create, name } },
    ...(blocked ? { blocked } : {}),
  };
}

function renameFolder(dir: Directory, obj: string, arg: string): Preview {
  const n = dir.node(obj);
  const id = folderId(n);
  const was = dir.catalog.folders.find((f) => f.id === id)?.name;
  if (was === undefined) throw new Error(`no folder "${id}"`);
  const name = arg.trim();
  const blocked = !name ? k("verb.folder.needName") : name === was ? k("verb.folder.same") : taken(dir, name, id) ? k("verb.folder.taken", { name }) : undefined;
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: k("verb.folder.renameTitle", { name: was }),
    lede: k("verb.folder.renameLede"),
    form: [{ inputs: [{ id: "name", label: k("verb.folder.name"), text: arg || was, placeholder: raw(was), with: (v) => v }] }],
    steps: [],
    changes: { rows: [{ lead: FOLDER_LEAD, name: k("verb.folder.name"), from: { faint: raw(was) }, to: name && name !== was ? { level: Level.Healthy, text: raw(name) } : { faint: k("verb.unchanged") } }] },
    stays: [{ level: Level.Healthy, title: k("verb.folder.itemsStay", { n: dir.kidIds(obj).length }), sub: k("verb.folder.itemsStaySub") }],
    go: k("verb.folder.renameGo"),
    note: k("verb.reversible"),
    effect: { folder: { op: FolderOp.Rename, id, name } },
    ...(blocked ? { blocked } : {}),
  };
}

function deleteFolder(dir: Directory, obj: string): Preview {
  const n = dir.node(obj);
  const items = dir.kidIds(obj).map((x) => dir.node(x));
  const rows: Delta[] = [
    { lead: FOLDER_LEAD, name: n.name, from: { faint: k("verb.folder.inVault") }, to: { level: Level.Warning, text: k("verb.folder.gone") } },
    ...items.map((x): Delta => ({ lead: { tile: LeadTile.Node, id: x.id }, name: x.name, from: { faint: n.name }, to: { faint: k("verb.folder.noFolder") } })),
  ];
  return {
    kind: PreviewKind.Ready,
    target: obj,
    title: k("verb.folder.deleteTitle", { name: n.name }),
    lede: k("verb.folder.deleteLede"),
    steps: [
      { title: k("verb.folder.deleteS1"), sub: k("verb.folder.deleteS1sub") },
      { title: k("verb.folder.deleteS2"), sub: k("verb.folder.deleteS2sub") },
    ],
    changes: { rows, count: items.length + 1 },
    stays: [{ level: Level.Healthy, title: k("verb.folder.itemsKept", { n: items.length }), sub: k("verb.folder.itemsKeptSub") }],
    go: k("verb.folder.deleteGo"),
    danger: true,
    effect: { folder: { op: FolderOp.Delete, id: folderId(n) } },
  };
}

/// A login with copies of its record: what `> merge` works on.
const merges = (n: Node | null) => !!n?.item && !n.item.deleted && n.item.kind === ItemKind.Login && (n.copies ?? 0) > 0;
const firstCopied = (dir: Directory) => dir.all().find((n) => merges(n))?.id ?? null;

const named = (_d: Directory, _o: string | null, arg: string): Text | null => (arg.trim() ? raw(arg.trim()) : null);

/// The verbs that open a document rather than a preview: the inspector
/// draws the item's form for them.
export const DOCUMENT_VERBS = new Set(["edit", "merge", "new", "new login", "new card", "new note", "new identity", "new ssh"]);

export const WRITE_VERBS: Verb[] = [
  { id: "edit", name: k("verb.edit"), icon: "edit", applies: editable, example: firstItem },
  { id: "merge", name: k("verb.merge"), icon: "merge", applies: merges, example: firstCopied },
  { id: "new", name: k("doc.newItem"), icon: "plus", applies: makesItems, argName: named },
  { id: "new login", name: k("verb.newLogin"), icon: "login", applies: makesItems, argName: named },
  { id: "new card", name: k("verb.newCard"), icon: "card", applies: makesItems, argName: named },
  { id: "new note", name: k("verb.newNote"), icon: "note", applies: makesItems, argName: named },
  { id: "new identity", name: k("verb.newIdentity"), icon: "identity", applies: makesItems, argName: named },
  { id: "new ssh", name: k("verb.newSsh"), icon: "key", applies: makesItems, argName: named },
  { id: "new folder", name: k("doc.newFolder"), icon: "folder", applies: makesFolders, preview: newFolder, argName: named },
  { id: "rename", name: k("doc.rename"), icon: "edit", applies: isFolder, preview: renameFolder, example: firstFolder, argName: named },
  { id: "delete", name: k("verb.delete"), icon: "trash", applies: isFolder, preview: deleteFolder, example: firstFolder },
];

/// Two verbs of one id (a collection's `> rename` and a folder's) as one:
/// each answers the nodes it applies to, under the writes' plainer name
/// (the path beside it says what is renamed).
function joined(a: Verb, b: Verb): Verb {
  const pick = (dir: Directory, obj: string | null) => (b.applies(obj && dir.has(obj) ? dir.node(obj) : null) ? b : a);
  return {
    ...a,
    name: b.name,
    applies: (n) => a.applies(n) || b.applies(n),
    preview: (dir, obj, arg) => {
      const v = pick(dir, obj === "root" ? null : obj);
      if (!v.preview) throw new Error(`the verb "${v.id}" has no preview`);
      return v.preview(dir, obj, arg);
    },
    refuses: (dir, obj) => (b.applies(dir.node(obj)) ? null : (a.refuses?.(dir, obj) ?? b.refuses?.(dir, obj) ?? null)),
    example: (dir) => a.example?.(dir) ?? b.example?.(dir) ?? null,
    argName: (dir, obj, arg) => (pick(dir, obj).argName ?? (() => null))(dir, obj, arg),
  };
}

/// The window's verbs with the writes' added: a verb whose id is already
/// there takes the nodes it applies to over from it.
export function withWriteVerbs(base: Verb[]): Verb[] {
  const out = [...base];
  for (const w of WRITE_VERBS) {
    const at = out.findIndex((v) => v.id === w.id);
    if (at < 0) out.push(w);
    else out[at] = joined(out[at]!, w);
  }
  return out;
}

/// Runs a folder's change through the app's writes; the new folder's id for
/// a new one.
export async function runFolderWrite(w: Writes, e: FolderWrite): Promise<string | null> {
  switch (e.op) {
    case FolderOp.Create:
      return w.createFolder(e.name);
    case FolderOp.Rename:
      await w.renameFolder(e.id, e.name);
      return null;
    case FolderOp.Delete:
      await w.deleteFolder(e.id);
      return null;
  }
}
