// The desktop app's writes: the daemon, through the window's Rust half.
//
// How a secret travels here:
// - A secret a person typed (`{ set }`) crosses this page once, as a plain
//   argument of `invoke`. The window's seal channel runs one way only — the
//   Rust half seals for the page (`seal.rs`), the page's key is derived for
//   decrypting and nothing on the Rust side opens what a page would seal — so
//   there is nothing to seal it with on the way out. It is the same path the
//   old window's edit form takes: Tauri's IPC inside the one process, where
//   the Rust half takes it as a `Secret` (wiped on drop) and sends it to the
//   daemon over the sealed control socket. The page holds it no longer than
//   the call.
// - A stored secret (`{ keep }`) is never read back to be re-sent: the edit
//   leaves that field out and the daemon keeps what it has.
// - A generated value comes back sealed (`invokeSecret`) and is opened here
//   only to be shown; `drop` lets go of it.
import { invoke } from "@tauri-apps/api/core";
import { type Change, type DraftField, type GeneratorOptions, type Invite, type ItemDraft, ItemKind, type MergeComparison, MergeField, type MergePlan, type MergeSlot, OrgRole, Permission, type SecretInput, type Writes, ChangeKind, GeneratorKind, enumParser } from "@keyward/core";
import { invokeSecret } from "./seal";
import type { Catalog as DaemonCatalog, ItemDetail as DaemonDetail, OrgMember, PendingEdit, VaultState } from "./types";

/// Bitwarden's numbers for the kinds an item can be created as.
const KIND_CODE: Record<ItemKind, number> = { [ItemKind.Login]: 1, [ItemKind.SecureNote]: 2, [ItemKind.Card]: 3, [ItemKind.Identity]: 4, [ItemKind.SshKey]: 5 };

/// Where the daemon's queue holds an edit (`keyward_core::edits::EditState`).
enum DaemonEditState {
  Pending = "pending",
  Pushed = "pushed",
  RolledBack = "rolled_back",
}
const parseDaemonEditState = enumParser(DaemonEditState, "the daemon's edit state");

/// A collection's level as the daemon spells it.
enum DaemonPermission {
  Manage = "manage",
  Edit = "edit",
  EditHidden = "edit_hidden",
  Read = "read",
  ReadHidden = "read_hidden",
}
const PERMISSION: Record<Permission, DaemonPermission> = { [Permission.Manage]: DaemonPermission.Manage, [Permission.Edit]: DaemonPermission.Edit, [Permission.EditHidden]: DaemonPermission.EditHidden, [Permission.Read]: DaemonPermission.Read, [Permission.ReadHidden]: DaemonPermission.ReadHidden };
type CollectionAccess = { id: string; permission: DaemonPermission };

/// `keyward_core::edits::CardEdit` and `IdentityEdit`: camelCase keys, the
/// same as the draft's.
type KindFields = Record<string, string>;

/// `keyward_core::edits::ItemEdit` as the daemon reads it. A key left out is
/// "leave it alone"; an empty string is "clear it".
type Edit = {
  name?: string;
  username?: string;
  password?: string;
  totp?: string;
  notes?: string;
  uris?: string[];
  custom?: { name: string; value: string; kind: number; linked_id: number | null }[];
  remove_custom?: string[];
  favorite?: boolean;
  /// `null` takes the item out of its folder.
  folder_id?: string | null;
  card?: KindFields;
  identity?: KindFields;
  reprompt?: boolean;
  ssh_key?: { source: "import"; private_key: string; passphrase: null };
};

/// What `item_detail` sends that `src/types.ts` does not spell out.
type Detail = DaemonDetail & { card?: KindFields | null; identity?: KindFields | null };

const CARD_KEYS = new Set(["cardholderName", "brand", "number", "expMonth", "expYear", "code"]);
const IDENTITY_KEYS = new Set([
  "title", "firstName", "middleName", "lastName", "username", "company", "email", "phone",
  "address1", "address2", "address3", "city", "state", "postalCode", "country", "ssn", "passportNumber", "licenseNumber",
]);
const LOGIN_KEYS = new Set(["username", "password", "totp"]);
/// Derived by the daemon from the private key; a value the window sends for
/// them would be a key that does not match its own public half.
const SSH_DERIVED = new Set(["publicKey", "fingerprint"]);

/// Bitwarden's custom field kinds.
const TEXT = 0;
const HIDDEN = 1;
const LINKED = 3;

const fail = (what: string): never => {
  throw new Error(what);
};

/// What a secret input asks of a field: a value to write, or nothing at all.
/// `keep` on an item that has nothing stored is a contradiction.
function secretValue(s: SecretInput, creating: boolean, field: string): string | undefined {
  if ("set" in s) return s.set;
  if ("clear" in s) return creating ? undefined : "";
  if (creating) fail(`a new item has no stored ${field} to keep`);
  return undefined;
}

/// A built-in field's value out of the draft: a plain value or a secret one.
function fieldValue(f: Extract<DraftField, { key: string }>, creating: boolean): string | undefined {
  return "value" in f ? f.value : secretValue(f.secret, creating, f.key);
}

/// The draft's built-in fields as the edit's, by kind. Only what changed goes
/// out on an update: `current` is what the daemon shows of the item now.
function builtIns(draft: ItemDraft, edit: Edit, creating: boolean, current: Detail | null) {
  const card: KindFields = {};
  const identity: KindFields = {};
  const shown = (key: string): string | null => current?.fields.find((f) => f.key === key && !f.hidden)?.value ?? null;
  const differs = (now: string | null | undefined, next: string) => creating || (now ?? "") !== next;

  for (const f of draft.fields) {
    if (!("key" in f)) continue;
    const next = fieldValue(f, creating);
    if (next === undefined) continue;
    const plain = "value" in f;
    switch (draft.kind) {
      case ItemKind.Login:
        if (!LOGIN_KEYS.has(f.key)) fail(`a login has no field "${f.key}"`);
        if (f.key === "username") {
          if (differs(shown("username"), next)) edit.username = next;
        } else if (plain) {
          fail(`a login's ${f.key} is a secret, not a plain value`);
        } else {
          edit[f.key as "password" | "totp"] = next;
        }
        break;
      case ItemKind.Card:
        if (!CARD_KEYS.has(f.key)) fail(`a card has no field "${f.key}"`);
        if (!plain || differs(current?.card?.[f.key], next)) card[f.key] = next;
        break;
      case ItemKind.Identity:
        if (!IDENTITY_KEYS.has(f.key)) fail(`an identity has no field "${f.key}"`);
        if (!plain || differs(current?.identity?.[f.key], next)) identity[f.key] = next;
        break;
      case ItemKind.SshKey:
        if (SSH_DERIVED.has(f.key)) break;
        if (f.key !== "privateKey") fail(`an ssh key has no field "${f.key}"`);
        if (next === "") fail("an ssh key item cannot lose its key");
        edit.ssh_key = { source: "import", private_key: next, passphrase: null };
        break;
      case ItemKind.SecureNote:
        fail(`a note has no field "${f.key}"`);
    }
  }
  if (Object.keys(card).length) edit.card = card;
  if (Object.keys(identity).length) edit.identity = identity;
}

/// Custom fields and the `kw-*` tags, which are custom fields too. On an
/// update a field the draft no longer has is removed, except a linked one:
/// a draft cannot express a link, so it is left as it is.
function customs(draft: ItemDraft, edit: Edit, creating: boolean, current: Detail | null, currentTags: Record<string, string>) {
  const out: NonNullable<Edit["custom"]> = [];
  const remove: string[] = [];
  const existing = new Map((current?.custom ?? []).map((c) => [c.name.trim().toLowerCase(), c]));
  const named = new Set<string>();

  for (const f of draft.fields) {
    if (!("custom" in f)) continue;
    const name = f.custom.trim();
    if (!name) fail("a custom field needs a name");
    if (name.toLowerCase().startsWith("kw-")) fail(`"${name}" is a tag's name: tags go in the draft's tags`);
    const low = name.toLowerCase();
    if (named.has(low)) fail(`the custom field "${name}" is named twice`);
    named.add(low);
    const was = existing.get(low);
    if (f.hidden) {
      const value = secretValue(f.secret, creating, name);
      if (value === undefined) {
        // Kept: the stored value stays, which only a field that is stored,
        // and hidden already, has.
        if (!creating && (!was || was.kind !== HIDDEN)) fail(`the custom field "${name}" has no hidden value to keep`);
        continue;
      }
      out.push({ name, value, kind: HIDDEN, linked_id: null });
    } else {
      // A checkbox stays a checkbox; anything else that is shown is text.
      const kind = was && was.kind !== HIDDEN && was.kind !== LINKED ? was.kind : TEXT;
      if (!creating && was && was.kind === kind && (was.value ?? "") === f.value) continue;
      out.push({ name, value: f.value, kind, linked_id: null });
    }
  }

  for (const [name, value] of Object.entries(draft.tags)) {
    if (!name.toLowerCase().startsWith("kw-")) fail(`the tag "${name}" is not a kw-* field`);
    if (!creating && currentTags[name] === value) continue;
    const was = existing.get(name.trim().toLowerCase());
    out.push({ name, value, kind: was && was.kind !== LINKED ? was.kind : TEXT, linked_id: null });
  }

  if (!creating) {
    for (const c of current?.custom ?? []) {
      const low = c.name.trim().toLowerCase();
      if (c.kind === LINKED) continue;
      const tag = low.startsWith("kw-");
      if (tag ? !Object.keys(draft.tags).some((t) => t.toLowerCase() === low) : !named.has(low)) remove.push(c.name);
    }
  }
  if (out.length) edit.custom = out;
  if (remove.length) edit.remove_custom = remove;
}

const sameList = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);
const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x));

const access = (a: Record<string, Permission>): CollectionAccess[] =>
  Object.entries(a).map(([id, p]) => ({ id, permission: PERMISSION[p] ?? fail(`an unknown permission "${p}"`) }));

/// A merge's slot as the daemon spells it (`keyward_core::merge::MergeSlot`).
type WireSlot = { field: string; name?: string };
const parseMergeField = enumParser(MergeField, "a merge field");
function slotOf(w: WireSlot): MergeSlot {
  const field = parseMergeField(w.field);
  if (field !== MergeField.Custom) return { field };
  return { field, name: typeof w.name === "string" ? w.name : fail("a custom merge field without a name") };
}
const wireSlot = (s: MergeSlot): WireSlot => (s.field === MergeField.Custom ? { field: s.field, name: s.name } : { field: s.field });
type WireComparison = { rows: { slot: WireSlot; secret: boolean; holders: { entry_id: string; group: number }[] }[] };

export class DaemonWrites implements Writes {
  /// `changed` is the backend's own announcer: a write tells the window what
  /// to read again the way a sync does.
  /// `membersChanged`: who reaches what changed (members, collections), so
  /// the backend reads the organisations' members again.
  constructor(
    private readonly changed: (c: Change) => void,
    private readonly membersChanged: () => void,
  ) {}

  async compareForMerge(itemIds: string[]): Promise<MergeComparison> {
    const c = await invoke<WireComparison>("merge_compare", { entryIds: itemIds });
    return { rows: c.rows.map((r) => ({ slot: slotOf(r.slot), secret: r.secret, holders: r.holders.map((h) => ({ itemId: h.entry_id, group: h.group })) })) };
  }

  /// The values move inside the daemon: the plan names records and fields.
  async merge(plan: MergePlan) {
    await invoke<VaultState>("merge_items", {
      plan: { keeper: plan.keeper, others: plan.others, takes: plan.takes.map((t) => ({ from: t.from, slot: wireSlot(t.slot), as_name: t.asName })) },
    });
    this.changed({ kind: ChangeKind.Catalog });
  }

  async verifyPassword(password: string) {
    return invoke<boolean>("verify_password", { password });
  }

  async create(draft: ItemDraft) {
    const edit: Edit = { name: draft.name, favorite: draft.favorite, reprompt: draft.reprompt };
    const notes = secretValue(draft.notes, true, "note");
    if (notes) edit.notes = notes;
    if (draft.kind === ItemKind.Login) edit.uris = draft.uris;
    else if (draft.uris.length) fail(`a ${draft.kind} has no addresses`);
    builtIns(draft, edit, true, null);
    customs(draft, edit, true, null, {});
    if (draft.kind === ItemKind.SshKey && !edit.ssh_key) fail("an ssh key item is made from a key");
    const id = await invoke<string>("item_create", {
      kind: KIND_CODE[draft.kind],
      folderId: draft.folderId,
      orgId: draft.orgId,
      collectionIds: draft.collectionIds,
      edit,
    });
    this.changed({ kind: ChangeKind.Catalog });
    return id;
  }

  async update(id: string, draft: ItemDraft) {
    const [current, catalog] = await Promise.all([
      invoke<Detail>("item_detail", { entryId: id }),
      invoke<DaemonCatalog>("vault_items"),
    ]);
    const summary = catalog.items.find((i) => i.id === id) ?? fail(`item ${id} is not in the catalogue`);
    if (draft.kind !== summary.kind) fail(`item ${id} is a ${summary.kind}, not a ${draft.kind}`);
    // Moving an item into, out of or between organisations re-seals all of
    // it with another key; the daemon does not do that yet.
    if ((draft.orgId ?? null) !== (summary.org_id ?? null)) fail("err.itemOrgChangeUnsupported");

    const edit: Edit = {};
    if (draft.name !== current.name) edit.name = draft.name;
    if (draft.favorite !== current.favorite) edit.favorite = draft.favorite;
    if (draft.reprompt !== current.reprompt) edit.reprompt = draft.reprompt;
    if ((draft.folderId ?? null) !== (summary.folder_id ?? null)) edit.folder_id = draft.folderId;
    if (draft.kind === ItemKind.Login) {
      if (!sameList(draft.uris, current.uris)) edit.uris = draft.uris;
    } else if (draft.uris.length) fail(`a ${draft.kind} has no addresses`);
    const notes = secretValue(draft.notes, false, "note");
    if (notes !== undefined) edit.notes = notes;
    builtIns(draft, edit, false, current);
    customs(draft, edit, false, current, summary.tags);

    if (Object.keys(edit).length) {
      const queued = await invoke<PendingEdit>("update_item", { entryId: id, edit });
      if (parseDaemonEditState(queued.state.state) === DaemonEditState.RolledBack) fail(`the edit of ${id} was rolled back`);
    }
    if (draft.orgId && !sameSet(draft.collectionIds, summary.collection_ids)) {
      await invoke<VaultState>("item_set_collections", { entryId: id, collectionIds: draft.collectionIds });
    } else if (!draft.orgId && draft.collectionIds.length) {
      fail("err.collectionsNeedOrg");
    }
    this.changed({ kind: ChangeKind.Item, id });
    this.changed({ kind: ChangeKind.Catalog });
  }

  async generate(opts: GeneratorOptions) {
    let value: string | null =
      opts.kind === GeneratorKind.Password
        ? await invokeSecret("generate_password", {
            spec: {
              length: opts.length,
              upper: opts.upper,
              lower: opts.lower,
              digits: opts.digits,
              symbols: opts.symbols,
              avoid_ambiguous: opts.avoidAmbiguous,
              symbols_inside_only: false,
            },
          })
        : await invokeSecret("generate_passphrase", {
            spec: { words: opts.words, separator: opts.separator, capitalize: opts.capitalize, number: opts.number },
          });
    return {
      get value() {
        if (value === null) throw new Error("the generated value was dropped");
        return value;
      },
      drop: () => {
        value = null;
      },
    };
  }

  async createFolder(name: string) {
    const id = await invoke<string>("folder_create", { name });
    this.changed({ kind: ChangeKind.Catalog });
    return id;
  }
  async renameFolder(id: string, name: string) {
    await invoke<VaultState>("rename_folder", { folderId: id, name });
    this.changed({ kind: ChangeKind.Catalog });
  }
  async deleteFolder(id: string) {
    await invoke<VaultState>("delete_folder", { folderId: id });
    this.changed({ kind: ChangeKind.Catalog });
  }

  async createCollection(orgId: string, name: string) {
    const id = await invoke<string>("collection_create", { orgId, name });
    this.membersChanged();
    this.changed({ kind: ChangeKind.Catalog });
    return id;
  }
  async renameCollection(orgId: string, id: string, name: string) {
    await invoke<VaultState>("rename_collection", { orgId, collectionId: id, name });
    this.membersChanged();
    this.changed({ kind: ChangeKind.Catalog });
  }
  async deleteCollection(orgId: string, id: string) {
    await invoke<VaultState>("delete_collection", { orgId, collectionId: id });
    this.membersChanged();
    this.changed({ kind: ChangeKind.Catalog });
  }

  async invite(orgId: string, invite: Invite) {
    await invoke<VaultState>("members_invite", {
      orgId,
      emails: invite.emails,
      role: role(invite.role),
      accessAll: invite.accessAll,
      access: invite.accessAll ? [] : access(invite.access),
    });
    this.membersChanged();
    this.changed({ kind: ChangeKind.Catalog });
  }
  async setMember(orgId: string, memberId: string, change: { role: OrgRole; accessAll: boolean; access: Record<string, Permission> }) {
    await invoke<VaultState>("member_set", {
      orgId,
      memberId,
      role: role(change.role),
      accessAll: change.accessAll,
      access: change.accessAll ? [] : access(change.access),
    });
    this.membersChanged();
    this.changed({ kind: ChangeKind.Catalog });
  }
  /// The member's five words, from the public key the daemon fetches for
  /// their user id now.
  async memberFingerprint(orgId: string, memberId: string) {
    const userId = await this.memberUserId(orgId, memberId);
    return invoke<string[]>("member_fingerprint", { orgId, memberId, userId });
  }
  /// Confirming hands the member the organisation key, sealed with their
  /// public key, which the daemon fetches by their user id — and seals to
  /// only while it still makes the words the person was shown.
  async confirmMember(orgId: string, memberId: string, fingerprint: string[]) {
    const userId = await this.memberUserId(orgId, memberId);
    await invoke<VaultState>("confirm_member", { orgId, memberId, userId, fingerprint });
    this.membersChanged();
    this.changed({ kind: ChangeKind.Catalog });
  }
  private async memberUserId(orgId: string, memberId: string): Promise<string> {
    const members = await invoke<OrgMember[]>("org_members", { orgId });
    const m = members.find((x) => x.id === memberId) ?? fail(`member ${memberId} is not in the organisation`);
    return m.user_id || fail(`member ${memberId} has no account to confirm yet`);
  }
  async removeMember(orgId: string, memberId: string) {
    await invoke<VaultState>("remove_member", { orgId, memberId });
    this.membersChanged();
    this.changed({ kind: ChangeKind.Catalog });
  }
}

/// The core's roles are the daemon's by name; a custom role is the server's
/// to define and is not handed out from here.
function role(r: OrgRole): Exclude<OrgRole, OrgRole.Custom> {
  if (r === OrgRole.Custom) fail("err.orgRoleNotYours");
  return r as Exclude<OrgRole, OrgRole.Custom>;
}
