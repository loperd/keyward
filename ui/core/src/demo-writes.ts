// The demo's writes, in memory over a `DemoBackend`: a saved draft changes
// the demo's catalogue and is announced like a sync, an item keeps the fields
// its draft gave it, and a secret typed into a draft is what the demo then
// reveals. A stored secret a draft keeps is never read here: the demo's own
// made-up value, or the one typed before, stays where it is. `failNext`
// makes the next call of that name refuse, so the stand can show a rollback.
import type { DemoBackend } from "./demo-backend";
import { DEMO_WRONG } from "./demo-backend";
import { DEMO_NOW } from "./demo";
import { detailOf, itemOf } from "./edit/draft";
import { t } from "./i18n";
import { type Item, type ItemDetail, type OrgRole, type Permission, type SecretRef, SecretField, MemberStatus } from "./model/types";
import { type GeneratorOptions, type Invite, type ItemDraft, type MergeComparison, type MergePlan, type MergeRow, type MergeSlot, type SecretInput, type Writes, GeneratorKind, MergeField } from "./writes";
import { type Field } from "./model/types";

/// A call of the writes, by name: what `failNext` names.
export enum Call {
  Create = "create",
  Update = "update",
  CreateFolder = "createFolder",
  RenameFolder = "renameFolder",
  DeleteFolder = "deleteFolder",
  CreateCollection = "createCollection",
  RenameCollection = "renameCollection",
  DeleteCollection = "deleteCollection",
  Invite = "invite",
  SetMember = "setMember",
  MemberFingerprint = "memberFingerprint",
  ConfirmMember = "confirmMember",
  RemoveMember = "removeMember",
  Merge = "merge",
  Regenerate = "regenerate",
}

/// The demo's fingerprint phrase for every member: Bitwarden's own example
/// words, so a person comparing on the stand sees what a real one looks like.
export const DEMO_FINGERPRINT: readonly string[] = ["turban", "deftly", "anime", "chatroom", "unselfish"];

const LOWER = "abcdefghijkmnopqrstuvwxyz";
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS = "23456789";
const SYMBOLS = "!@#$%^&*-_=+?";
const AMBIGUOUS = { lower: "l", upper: "IO", digits: "01" };
/// A short list for the demo's passphrases; a real backend has its own.
const WORDS = (
  "amber anchor apple arrow aspen atlas basil beacon birch bison cabin canyon cedar cinder clover cobalt comet coral delta dune ember fable falcon fern fjord flint galaxy garnet glacier harbor hazel heron indigo iris jasper juniper kelp lagoon lantern lemon lily lotus maple marble meadow mint nebula oak olive onyx opal orbit otter pebble pine plum quartz raven reef river saffron sage sparrow spruce stone thistle tide timber tulip velvet willow"
).split(" ");

/// A random whole number below `n`, from the platform's random source.
function below(n: number): number {
  const b = new Uint32Array(1);
  crypto.getRandomValues(b);
  return b[0]! % n;
}
const pick = (chars: string) => chars[below(chars.length)]!;
function shuffle(xs: string[]): string[] {
  for (let i = xs.length - 1; i > 0; i--) {
    const j = below(i + 1);
    [xs[i], xs[j]] = [xs[j]!, xs[i]!];
  }
  return xs;
}

/// A password of the sets asked for, at least one character of each.
export function generatePassword(o: Extract<GeneratorOptions, { kind: GeneratorKind.Password }>): string {
  const sets = [
    o.lower ? LOWER + (o.avoidAmbiguous ? "" : AMBIGUOUS.lower) : "",
    o.upper ? UPPER + (o.avoidAmbiguous ? "" : AMBIGUOUS.upper) : "",
    o.digits ? DIGITS + (o.avoidAmbiguous ? "" : AMBIGUOUS.digits) : "",
    o.symbols ? SYMBOLS : "",
  ].filter(Boolean);
  if (!sets.length) throw new Error("a password needs at least one set of characters");
  if (o.length < sets.length) throw new Error(`a password of ${o.length} cannot hold ${sets.length} sets`);
  const all = sets.join("");
  const out = sets.map(pick);
  while (out.length < o.length) out.push(pick(all));
  return shuffle(out).join("");
}
export function generatePassphrase(o: Extract<GeneratorOptions, { kind: GeneratorKind.Passphrase }>): string {
  if (o.words < 1) throw new Error("a passphrase needs at least one word");
  const ws = Array.from({ length: o.words }, () => {
    const w = WORDS[below(WORDS.length)]!;
    return o.capitalize ? w[0]!.toUpperCase() + w.slice(1) : w;
  });
  if (o.number) {
    const i = below(ws.length);
    ws[i] = ws[i]! + pick(DIGITS);
  }
  return ws.join(o.separator);
}

const secretOfDraft = (d: ItemDraft, key: string): SecretInput | null => {
  const f = d.fields.find((x) => "key" in x && x.key === key);
  return f && "secret" in f ? f.secret : null;
};
/// The draft's key for each secret the demo names by reference.
const SECRET_KEY: Partial<Record<SecretRef["field"], string>> = { [SecretField.Password]: "password", [SecretField.Totp]: "totp", [SecretField.CardNumber]: "number", [SecretField.CardCode]: "code", [SecretField.PrivateKey]: "privateKey" };

export class DemoWrites implements Writes {
  /// The next call of this name is refused.
  failNext: Call | null = null;
  /// How long a call takes, so a pending save can be seen.
  delay = 400;
  /// What each call was asked, for the tests: never a secret's value.
  readonly calls: string[] = [];
  private readonly details = new Map<string, ItemDetail>();
  private readonly values = new Map<string, string>();
  private seq = 0;

  constructor(private readonly backend: DemoBackend) {
    backend.written = {
      item: (id) => this.details.get(id) ?? null,
      value: (ref) => this.values.get(this.refKey(ref)) ?? null,
    };
  }

  private refKey(ref: SecretRef) {
    return ref.field === SecretField.Custom ? `${ref.itemId}\0custom\0${ref.name}` : `${ref.itemId}\0${ref.field}`;
  }
  private async call(what: Call, detail: string) {
    this.calls.push(`${what} ${detail}`);
    await new Promise((r) => setTimeout(r, this.delay));
    if (this.failNext === what) {
      this.failNext = null;
      throw new Error(t("err.forbidden"));
    }
  }

  async verifyPassword(password: string): Promise<boolean> {
    return password !== DEMO_WRONG;
  }

  /// A draft's secrets taken in: a typed value is kept for the demo to
  /// reveal, a cleared one forgotten, a kept one left as it is.
  private take(id: string, d: ItemDraft) {
    const put = (ref: SecretRef, s: SecretInput | null) => {
      if (!s) return;
      const key = this.refKey(ref);
      if ("set" in s) this.values.set(key, s.set);
      else if ("clear" in s) this.values.delete(key);
    };
    for (const [field, key] of Object.entries(SECRET_KEY)) put({ itemId: id, field: field as Exclude<SecretField, SecretField.Custom> }, secretOfDraft(d, key!));
    put({ itemId: id, field: SecretField.Notes }, d.notes);
    for (const f of d.fields) {
      if (!("custom" in f)) continue;
      if (f.hidden) put({ itemId: id, field: SecretField.Custom, name: f.custom }, f.secret);
      else this.values.set(this.refKey({ itemId: id, field: SecretField.Custom, name: f.custom }), f.value);
    }
    const u = d.fields.find((x) => "key" in x && x.key === "username");
    if (u && "value" in u) this.values.set(this.refKey({ itemId: id, field: SecretField.Username }), u.value);
  }

  async create(d: ItemDraft): Promise<string> {
    await this.call(Call.Create, `${d.kind} ${d.name}`);
    const id = `new-${++this.seq}`;
    const now = DEMO_NOW.toISOString();
    const base: Item = {
      id,
      name: d.name,
      kind: d.kind,
      subtitle: null,
      folderId: null,
      orgId: null,
      collectionIds: [],
      uris: [],
      tags: {},
      hasTotp: false,
      passkeys: 0,
      favorite: false,
      deleted: false,
      reprompt: false,
      revised: now,
      passwordRevised: secretOfDraft(d, "password") ? now : null,
      expires: null,
      reused: 0,
      reuseGroup: null,
    };
    const item = itemOf(d, base);
    this.take(id, d);
    this.details.set(id, detailOf(d, item, null));
    this.backend.mutate((data) => data.items.push(item));
    return id;
  }

  async update(id: string, d: ItemDraft): Promise<void> {
    await this.call(Call.Update, `${id} ${d.kind} ${d.name}`);
    const prev = await this.backend.item(id);
    const pw = secretOfDraft(d, "password");
    const item = { ...itemOf(d, prev.item), revised: DEMO_NOW.toISOString(), ...(pw && "set" in pw ? { passwordRevised: DEMO_NOW.toISOString(), reused: 0, reuseGroup: null } : {}) };
    this.take(id, d);
    this.details.set(id, detailOf(d, item, prev));
    this.backend.mutate((data) => {
      const at = data.items.findIndex((i) => i.id === id);
      if (at < 0) throw new Error(`no item "${id}"`);
      data.items[at] = item;
      // A password made anew shares nothing: its partners lose the one
      // they shared with it.
      if (pw && "set" in pw && prev.item.reuseGroup !== null) {
        const rest = data.items.filter((i) => i.reuseGroup === prev.item.reuseGroup);
        for (const r of rest) {
          r.reused = Math.max(0, rest.length - 1);
          if (rest.length < 2) r.reuseGroup = null;
        }
      }
    });
  }

  /// The demo's item gets a new password where its keys would be: the window
  /// never sees it.
  async regenerate(itemId: string): Promise<void> {
    await this.call(Call.Regenerate, itemId);
  }

  async generate(opts: GeneratorOptions): Promise<{ value: string; drop: () => void }> {
    let value: string | null = opts.kind === GeneratorKind.Password ? generatePassword(opts) : generatePassphrase(opts);
    return {
      get value() {
        if (value === null) throw new Error("a generated value was read after it was dropped");
        return value;
      },
      drop: () => {
        value = null;
      },
    };
  }

  /// What the demo holds in a slot of an item: the value typed into it, or
  /// its made-up one — a password shared by a reuse group is one value.
  private async slots(id: string): Promise<{ detail: ItemDetail; held: Map<string, { slot: MergeSlot; secret: boolean; value: string; field: Field | null }> }> {
    const detail = await this.backend.item(id);
    const it = detail.item;
    const held = new Map<string, { slot: MergeSlot; secret: boolean; value: string; field: Field | null }>();
    const valueOf = async (ref: SecretRef) => {
      if (ref.field === SecretField.Password && it.reuseGroup !== null && !this.values.has(this.refKey(ref))) return `reuse-${it.reuseGroup}`;
      const r = await this.backend.reveal(ref);
      const v = r.value;
      r.drop();
      return v;
    };
    for (const f of detail.fields) {
      const builtin = f.key === "username" ? MergeField.Username : f.key === "password" ? MergeField.Password : f.key === "totp" ? MergeField.Totp : null;
      const slot: MergeSlot | null = builtin ? { field: builtin } : f.key === null ? { field: MergeField.Custom, name: f.label } : null;
      if (!slot) continue;
      const secret = f.value === null && !!f.secret;
      const value = f.value ?? (f.secret ? await valueOf(f.secret) : "");
      if (value) held.set(slot.field === MergeField.Custom ? `custom:${slot.name.toLowerCase()}` : slot.field, { slot, secret: secret && builtin !== MergeField.Username, value, field: f });
    }
    if (detail.notes) held.set(MergeField.Notes, { slot: { field: MergeField.Notes }, secret: true, value: await valueOf(detail.notes), field: null });
    if (it.passkeys > 0) held.set(MergeField.Passkeys, { slot: { field: MergeField.Passkeys }, secret: false, value: `passkeys-${id}`, field: null });
    return { detail, held };
  }

  async compareForMerge(itemIds: string[]): Promise<MergeComparison> {
    const all = await Promise.all(itemIds.map((id) => this.slots(id)));
    const rows = new Map<string, MergeRow & { values: string[] }>();
    all.forEach(({ held }, n) => {
      for (const [key, h] of held) {
        let row = rows.get(key);
        if (!row) rows.set(key, (row = { slot: h.slot, secret: h.secret, holders: [], values: [] }));
        row.secret ||= h.secret;
        let group = row.values.indexOf(h.value);
        if (group < 0) group = row.values.push(h.value) - 1;
        row.holders.push({ itemId: itemIds[n]!, group });
      }
    });
    return { rows: [...rows.values()].map(({ values: _, ...r }) => r) };
  }

  async merge(plan: MergePlan): Promise<void> {
    await this.call(Call.Merge, `${plan.keeper} ${plan.others.join(" ")} ${plan.takes.map((t) => `${t.slot.field}${t.asName ? `=${t.asName}` : ""}`).join(" ")}`);
    const keeper = await this.slots(plan.keeper);
    const others = new Map(await Promise.all(plan.others.map(async (id) => [id, await this.slots(id)] as const)));
    const detail = structuredClone(keeper.detail);
    const it = detail.item;
    for (const [, o] of others) for (const u of o.detail.item.uris) if (!it.uris.some((x) => x.toLowerCase() === u.toLowerCase())) it.uris.push(u);
    const BUILTIN: Record<Exclude<MergeField, MergeField.Custom | MergeField.Passkeys>, Exclude<SecretField, SecretField.Custom>> = {
      [MergeField.Username]: SecretField.Username,
      [MergeField.Password]: SecretField.Password,
      [MergeField.Totp]: SecretField.Totp,
      [MergeField.Notes]: SecretField.Notes,
    };
    const ref = (slot: MergeSlot): SecretRef => {
      if (slot.field === MergeField.Custom) return { itemId: it.id, field: SecretField.Custom, name: slot.name };
      if (slot.field === MergeField.Passkeys) throw new Error("passkeys are not a secret field");
      return { itemId: it.id, field: BUILTIN[slot.field] };
    };
    for (const take of plan.takes) {
      const from = others.get(take.from);
      if (!from) throw new Error(`a take from "${take.from}", which is not merged`);
      if (take.slot.field === MergeField.Passkeys) {
        it.passkeys += from.detail.item.passkeys;
        continue;
      }
      const key = take.slot.field === MergeField.Custom ? `custom:${take.slot.name.toLowerCase()}` : take.slot.field;
      const h = from.held.get(key);
      if (!h) throw new Error(t("err.mergeFieldGone"));
      if (take.asName) {
        const r: SecretRef = { itemId: it.id, field: SecretField.Custom, name: take.asName };
        this.values.set(this.refKey(r), h.value);
        detail.fields.push({ key: null, label: take.asName, value: h.secret ? null : h.value, secret: r, mono: true });
        continue;
      }
      const r = ref(take.slot);
      this.values.set(this.refKey(r), h.value);
      if (take.slot.field === MergeField.Notes) {
        detail.notes = r;
        continue;
      }
      const at = detail.fields.findIndex((f) => (take.slot.field === MergeField.Custom ? f.key === null && f.label.toLowerCase() === take.slot.name.toLowerCase() : f.key === take.slot.field));
      const field: Field = { key: take.slot.field === MergeField.Custom ? null : take.slot.field, label: take.slot.field === MergeField.Custom ? take.slot.name : take.slot.field, value: h.secret ? null : h.value, secret: r, mono: true };
      if (at < 0) detail.fields.push(field);
      else detail.fields[at] = field;
      if (take.slot.field === MergeField.Username) it.subtitle = h.value;
      if (take.slot.field === MergeField.Totp) it.hasTotp = true;
      if (take.slot.field === MergeField.Password) Object.assign(it, { passwordRevised: DEMO_NOW.toISOString(), reuseGroup: from.detail.item.reuseGroup });
    }
    it.revised = DEMO_NOW.toISOString();
    this.details.set(it.id, detail);
    this.backend.mutate((data) => {
      const at = data.items.findIndex((i) => i.id === it.id);
      if (at < 0) throw new Error(`no item "${it.id}"`);
      data.items[at] = it;
    });
    await this.backend.trash(plan.others);
  }

  async createFolder(name: string): Promise<string> {
    await this.call(Call.CreateFolder, name);
    const id = `folder-${++this.seq}`;
    this.backend.mutate((data) => data.folders.push({ id, name }));
    return id;
  }
  async renameFolder(id: string, name: string): Promise<void> {
    await this.call(Call.RenameFolder, `${id} ${name}`);
    this.backend.mutate((data) => {
      const f = data.folders.find((x) => x.id === id);
      if (!f) throw new Error(`no folder "${id}"`);
      f.name = name;
    });
  }
  async deleteFolder(id: string): Promise<void> {
    await this.call(Call.DeleteFolder, id);
    this.backend.mutate((data) => {
      if (!data.folders.some((x) => x.id === id)) throw new Error(`no folder "${id}"`);
      data.folders = data.folders.filter((x) => x.id !== id);
      for (const i of data.items) if (i.folderId === id) i.folderId = null;
    });
  }

  async createCollection(orgId: string, name: string): Promise<string> {
    await this.call(Call.CreateCollection, `${orgId} ${name}`);
    const id = `coll-${++this.seq}`;
    this.backend.mutate((data) => data.collections.push({ id, orgId, name, readOnly: false }));
    return id;
  }
  async renameCollection(orgId: string, id: string, name: string): Promise<void> {
    await this.call(Call.RenameCollection, `${orgId} ${id} ${name}`);
    this.backend.mutate((data) => {
      const c = data.collections.find((x) => x.id === id && x.orgId === orgId);
      if (!c) throw new Error(`no collection "${id}" in "${orgId}"`);
      c.name = name;
    });
  }
  async deleteCollection(orgId: string, id: string): Promise<void> {
    await this.call(Call.DeleteCollection, `${orgId} ${id}`);
    this.backend.mutate((data) => {
      if (!data.collections.some((x) => x.id === id && x.orgId === orgId)) throw new Error(`no collection "${id}" in "${orgId}"`);
      data.collections = data.collections.filter((x) => x.id !== id);
      for (const i of data.items) i.collectionIds = i.collectionIds.filter((c) => c !== id);
      for (const m of data.members) delete m.access[id];
    });
  }

  async invite(orgId: string, inv: Invite): Promise<void> {
    await this.call(Call.Invite, `${orgId} ${inv.emails.join(",")} ${inv.role}`);
    this.backend.mutate((data) => {
      for (const email of inv.emails)
        data.members.push({ id: `m-${++this.seq}`, orgId, name: null, email, role: inv.role, status: MemberStatus.Invited, twoFactor: null, accessAll: inv.accessAll, access: { ...inv.access }, isYou: false });
    });
  }
  async setMember(orgId: string, memberId: string, change: { role: OrgRole; accessAll: boolean; access: Record<string, Permission> }): Promise<void> {
    await this.call(Call.SetMember, `${orgId} ${memberId} ${change.role}`);
    this.backend.mutate((data) => {
      const m = this.member(data.members, orgId, memberId);
      m.role = change.role;
      m.accessAll = change.accessAll;
      m.access = { ...change.access };
    });
  }
  async memberFingerprint(orgId: string, memberId: string): Promise<string[]> {
    await this.call(Call.MemberFingerprint, `${orgId} ${memberId}`);
    this.member((await this.backend.catalog()).members, orgId, memberId);
    return [...DEMO_FINGERPRINT];
  }
  async confirmMember(orgId: string, memberId: string, fingerprint: string[]): Promise<void> {
    await this.call(Call.ConfirmMember, `${orgId} ${memberId}`);
    if (fingerprint.join(" ") !== DEMO_FINGERPRINT.join(" ")) throw new Error(t("err.fingerprintChanged"));
    this.backend.mutate((data) => {
      this.member(data.members, orgId, memberId).status = MemberStatus.Confirmed;
    });
  }
  async removeMember(orgId: string, memberId: string): Promise<void> {
    await this.call(Call.RemoveMember, `${orgId} ${memberId}`);
    this.backend.mutate((data) => {
      this.member(data.members, orgId, memberId);
      data.members = data.members.filter((m) => !(m.id === memberId && m.orgId === orgId));
    });
  }
  private member<M extends { id: string; orgId: string }>(ms: M[], orgId: string, id: string): M {
    const m = ms.find((x) => x.id === id && x.orgId === orgId);
    if (!m) throw new Error(`no member "${id}" in "${orgId}"`);
    return m;
  }
}
