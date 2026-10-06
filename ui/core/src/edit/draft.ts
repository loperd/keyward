// An item as a person edits it, before it is a draft: what the form holds,
// how it is read from an opened item, how it is set up for a new one in a
// place, and how it becomes the `ItemDraft` the backend is sent. A secret
// already stored is never in the form: its slot says only that it is there,
// and the draft names it with `keep`. Pure.
import type { Key, Text } from "../i18n";
import { type Field, type Item, type ItemDetail, ItemKind, type SecretRef, SecretField } from "../model/types";
import { type Directory, NodeKind } from "../path/directory";
import { type DraftField, type GeneratorOptions, type ItemDraft, type SecretInput, GeneratorKind } from "../writes";

/// A built-in field of a kind, as the form draws it.
export type FieldSpec = {
  key: string;
  label: Key;
  secret?: boolean;
  mono?: boolean;
  /// Several lines: a private key, a note.
  multiline?: boolean;
  /// The password: offers the generator.
  generate?: boolean;
  /// Worked out from another field (a key's fingerprint): shown, not typed.
  readOnly?: boolean;
  /// Two short inputs on one row (a card's month and year).
  parts?: [string, string];
  placeholder?: Key;
};

export const KIND_FIELDS: Record<ItemKind, FieldSpec[]> = {
  [ItemKind.Login]: [
    { key: "username", label: "field.username", mono: true },
    { key: "password", label: "field.password", secret: true, mono: true, generate: true },
    { key: "totp", label: "edit.totpKey", secret: true, mono: true },
  ],
  [ItemKind.Card]: [
    { key: "cardholderName", label: "field.cardholder" },
    { key: "brand", label: "field.brand" },
    { key: "number", label: "field.cardNumber", secret: true, mono: true },
    { key: "expiry", label: "field.expiry", mono: true, parts: ["expMonth", "expYear"] },
    { key: "code", label: "field.cardCode", secret: true, mono: true },
  ],
  [ItemKind.Identity]: [
    { key: "firstName", label: "edit.firstName" },
    { key: "lastName", label: "edit.lastName" },
    { key: "email", label: "field.email", mono: true },
    { key: "phone", label: "field.phone", mono: true },
    { key: "company", label: "field.company" },
  ],
  [ItemKind.SecureNote]: [],
  [ItemKind.SshKey]: [
    { key: "privateKey", label: "field.privateKey", secret: true, mono: true, multiline: true, placeholder: "edit.pasteKey" },
    { key: "publicKey", label: "field.publicKey", mono: true },
    { key: "fingerprint", label: "field.fingerprint", mono: true, readOnly: true },
  ],
};

/// The kinds a new item can be, in the order the switch shows them, with
/// the verb that names each and its icon.
export const KINDS: { kind: ItemKind; verb: string; icon: string; label: Key }[] = [
  { kind: ItemKind.Login, verb: "new login", icon: "login", label: "kind.login" },
  { kind: ItemKind.Card, verb: "new card", icon: "card", label: "kind.card" },
  { kind: ItemKind.SecureNote, verb: "new note", icon: "note", label: "kind.secure_note" },
  { kind: ItemKind.Identity, verb: "new identity", icon: "identity", label: "kind.identity" },
  { kind: ItemKind.SshKey, verb: "new ssh", icon: "key", label: "kind.ssh_key" },
];
/// The kind a creating verb makes; `undefined` for a verb that makes none.
export function kindOfVerb(verb: string | null): ItemKind | undefined {
  if (verb === "new") return ItemKind.Login;
  return KINDS.find((k) => k.verb === verb)?.kind;
}

/// A secret's slot: whether one is stored, and what the person did with it.
/// `input: null` is untouched.
export type SecretSlot = { stored: boolean; input: SecretInput | null };
export type CustomField = { name: string; hidden: boolean; value: string; secret: SecretSlot; mono?: boolean };
/// Where an item lives: an organisation's collections, or a personal folder.
export type Placement = { orgId: string | null; folderId: string | null; collectionIds: string[] };

export type Form = {
  kind: ItemKind;
  name: string;
  place: Placement;
  favorite: boolean;
  reprompt: boolean;
  uris: string[];
  notes: SecretSlot;
  values: Record<string, string>;
  secrets: Record<string, SecretSlot>;
  custom: CustomField[];
  tags: Record<string, string>;
};

const EMPTY_SLOT: SecretSlot = { stored: false, input: null };
const STORED_SLOT: SecretSlot = { stored: true, input: null };

/// The opened item's field keys → the draft's.
const FROM_DETAIL: Record<string, string> = {
  username: "username",
  password: "password",
  totp: "totp",
  cardholder: "cardholderName",
  brand: "brand",
  cardNumber: "number",
  cardCode: "code",
  email: "email",
  phone: "phone",
  company: "company",
  privateKey: "privateKey",
  publicKey: "publicKey",
  fingerprint: "fingerprint",
};
/// Shown on the page, worked out where the keys are: never part of a draft.
const DERIVED = new Set(["algorithm"]);

function blank(kind: ItemKind): Pick<Form, "values" | "secrets"> {
  const values: Record<string, string> = {};
  const secrets: Record<string, SecretSlot> = {};
  for (const f of KIND_FIELDS[kind]) {
    if (f.parts) for (const p of f.parts) values[p] = "";
    else if (f.secret) secrets[f.key] = EMPTY_SLOT;
    else values[f.key] = "";
  }
  return { values, secrets };
}

/// The form over an opened item: values as they are, stored secrets as
/// slots that hold nothing.
export function formFromDetail(d: ItemDetail): Form {
  const it = d.item;
  const { values, secrets } = blank(it.kind);
  const custom: CustomField[] = [];
  for (const f of d.fields) {
    if (f.key !== null && DERIVED.has(f.key)) continue;
    if (f.key === "expiry") {
      const m = /^(\d{1,2})\s*\/\s*(\d{2,4})$/.exec(f.value ?? "");
      if (!m) throw new Error(`a card's expiry is not "MM / YYYY": ${f.value}`);
      values.expMonth = m[1]!;
      values.expYear = m[2]!;
      continue;
    }
    if (f.key === "fullName") {
      const v = (f.value ?? "").trim();
      const at = v.indexOf(" ");
      values.firstName = at < 0 ? v : v.slice(0, at);
      values.lastName = at < 0 ? "" : v.slice(at + 1);
      continue;
    }
    const key = f.key !== null ? FROM_DETAIL[f.key] : undefined;
    if (key) {
      if (f.value !== null) values[key] = f.value;
      else if (f.secret) secrets[key] = STORED_SLOT;
      else throw new Error(`the field "${f.key}" has neither a value nor a reference`);
      continue;
    }
    // A name a person made up, or a built-in key the form has no row for:
    // kept as the custom field it is in the vault.
    if (f.value !== null) custom.push({ name: f.label, hidden: false, value: f.value, secret: EMPTY_SLOT, mono: f.mono });
    else if (f.secret) custom.push({ name: f.label, hidden: true, value: "", secret: STORED_SLOT });
    else throw new Error(`the field "${f.label}" has neither a value nor a reference`);
  }
  return {
    kind: it.kind,
    name: it.name,
    place: { orgId: it.orgId, folderId: it.folderId, collectionIds: [...it.collectionIds] },
    favorite: it.favorite,
    reprompt: it.reprompt,
    uris: [...it.uris],
    notes: d.notes ? STORED_SLOT : EMPTY_SLOT,
    values,
    secrets,
    custom,
    tags: { ...it.tags },
  };
}

/// A new item's form, in a place.
export function formForNew(kind: ItemKind, place: Placement, name = ""): Form {
  return { kind, name, place, favorite: false, reprompt: false, uris: kind === ItemKind.Login ? [""] : [], notes: EMPTY_SLOT, ...blank(kind), custom: [], tags: {} };
}

/// Another kind for a form not saved yet: what both kinds have is kept.
export function switchKind(f: Form, kind: ItemKind): Form {
  if (f.kind === kind) return f;
  const b = blank(kind);
  for (const k of Object.keys(b.values)) if (k in f.values) b.values[k] = f.values[k]!;
  for (const k of Object.keys(b.secrets)) if (k in f.secrets) b.secrets[k] = f.secrets[k]!;
  return { ...f, kind, ...b, uris: kind === ItemKind.Login ? (f.uris.length ? f.uris : [""]) : f.uris };
}

/// Where a new item made at a node goes: the node's folder or collection,
/// an organisation's first collection one may write to, or the personal
/// vault.
export function placementOf(dir: Directory, nodeId: string | null): Placement {
  const personal: Placement = { orgId: null, folderId: null, collectionIds: [] };
  if (!nodeId || !dir.has(nodeId)) return personal;
  const n = dir.node(nodeId);
  if (n.item) return { orgId: n.item.orgId, folderId: n.item.folderId, collectionIds: [...n.item.collectionIds] };
  if (n.kind === NodeKind.Folder) return { ...personal, folderId: n.id.slice("folder:".length) };
  if (n.kind === NodeKind.Collection) {
    const c = dir.catalog.collections.find((x) => `collection:${x.id}` === n.id);
    if (!c) throw new Error(`no collection for "${n.id}"`);
    return { orgId: c.orgId, folderId: null, collectionIds: [c.id] };
  }
  const org = dir.orgOf(nodeId);
  if (org) {
    const orgId = org.slice("org:".length);
    const first = dir.catalog.collections.find((c) => c.orgId === orgId && !c.readOnly);
    return { orgId, folderId: null, collectionIds: first ? [first.id] : [] };
  }
  return personal;
}

/// A place a form may choose: its value in the select, its words.
export type PlaceOption = { value: string; label: Text; place: Placement };
export const placeValue = (p: Placement) => (p.orgId ? `c:${p.orgId}:${p.collectionIds[0] ?? ""}` : p.folderId ? `f:${p.folderId}` : "p");

/// The places an item can go. An item that exists stays with its owner:
/// moving it between the personal vault and an organisation is sharing, a
/// verb of its own.
export function placeOptions(dir: Directory, owner?: { orgId: string | null }): PlaceOption[] {
  const out: PlaceOption[] = [];
  const personal = owner === undefined || owner.orgId === null;
  if (personal) {
    out.push({ value: "p", label: { key: "personal" }, place: { orgId: null, folderId: null, collectionIds: [] } });
    for (const f of dir.catalog.folders)
      out.push({ value: `f:${f.id}`, label: { key: "map.placeJoin", args: { a: { key: "personal" }, b: { raw: f.name } } }, place: { orgId: null, folderId: f.id, collectionIds: [] } });
  }
  for (const o of dir.catalog.orgs) {
    if (owner !== undefined && owner.orgId !== o.id) continue;
    for (const c of dir.catalog.collections.filter((x) => x.orgId === o.id && !x.readOnly))
      out.push({ value: `c:${o.id}:${c.id}`, label: { key: "map.placeJoin", args: { a: { raw: o.name }, b: { raw: c.name } } }, place: { orgId: o.id, folderId: null, collectionIds: [c.id] } });
  }
  return out;
}

/// What a slot sends: a typed value, the stored one kept, or the stored one
/// cleared. An empty "replace" keeps what is stored; nothing is sent for a
/// slot that holds nothing and was left alone.
export function secretOf(s: SecretSlot): SecretInput | null {
  const i = s.input;
  if (i && "set" in i && i.set !== "") return { set: i.set };
  if (i && "clear" in i) return s.stored ? { clear: true } : null;
  return s.stored ? { keep: true } : null;
}

/// The secret slots a form has, by id: a built-in key, `notes`, or
/// `custom:<index>`. A slot being typed into holds `{ set: "" }` in the form
/// — a marker: the value itself stays in its field until the save takes it.
export function typedSlots(f: Form): string[] {
  const typed = (s: SecretSlot) => !!s.input && "set" in s.input;
  return [
    ...Object.entries(f.secrets).filter(([, s]) => typed(s)).map(([k]) => k),
    ...(typed(f.notes) ? ["notes"] : []),
    ...f.custom.flatMap((c, i) => (c.hidden && typed(c.secret) ? [`custom:${i}`] : [])),
  ];
}
/// The form with the values taken from its fields put into its slots, for
/// the one moment the draft is made.
export function fillSecrets(f: Form, values: ReadonlyMap<string, string>): Form {
  const fill = (id: string, s: SecretSlot): SecretSlot => (values.has(id) && s.input && "set" in s.input ? { ...s, input: { set: values.get(id)! } } : s);
  return {
    ...f,
    secrets: Object.fromEntries(Object.entries(f.secrets).map(([k, s]) => [k, fill(k, s)])),
    notes: fill("notes", f.notes),
    custom: f.custom.map((c, i) => (c.hidden ? { ...c, secret: fill(`custom:${i}`, c.secret) } : c)),
  };
}

/// What is missing before the form can be saved.
export function problems(f: Form): Key[] {
  const out: Key[] = [];
  if (!f.name.trim()) out.push("edit.needName");
  if (f.place.orgId && !f.place.collectionIds.length) out.push("edit.needCollection");
  return out;
}

/// The form as the backend is sent it.
export function draftOf(f: Form): ItemDraft {
  if (problems(f).length) throw new Error(`a draft was asked for a form that cannot be saved: ${problems(f).join(", ")}`);
  const fields: DraftField[] = [];
  for (const spec of KIND_FIELDS[f.kind]) {
    if (spec.parts) {
      for (const p of spec.parts) fields.push({ key: p, value: f.values[p] ?? "" });
      continue;
    }
    if (spec.secret) {
      const s = secretOf(f.secrets[spec.key] ?? EMPTY_SLOT);
      if (s) fields.push({ key: spec.key, secret: s });
      continue;
    }
    fields.push({ key: spec.key, value: f.values[spec.key] ?? "" });
  }
  for (const c of f.custom) {
    if (!c.name.trim()) continue;
    if (!c.hidden) {
      fields.push({ custom: c.name, value: c.value, hidden: false });
      continue;
    }
    const s = secretOf(c.secret);
    if (s) fields.push({ custom: c.name, secret: s, hidden: true });
  }
  return {
    kind: f.kind,
    name: f.name.trim(),
    folderId: f.place.orgId ? null : f.place.folderId,
    orgId: f.place.orgId,
    collectionIds: f.place.orgId ? [...f.place.collectionIds] : [],
    favorite: f.favorite,
    reprompt: f.reprompt,
    uris: f.kind === ItemKind.Login ? f.uris.map((u) => u.trim()).filter(Boolean) : [],
    notes: secretOf(f.notes) ?? { clear: true },
    fields,
    tags: { ...f.tags },
  };
}

// ---------- a draft read back: what the page shows once it is saved ----------

const fieldValue = (d: ItemDraft, key: string): string | null => {
  const f = d.fields.find((x) => "key" in x && x.key === key);
  return f && "value" in f ? f.value : null;
};
const fieldSecret = (d: ItemDraft, key: string): SecretInput | null => {
  const f = d.fields.find((x) => "key" in x && x.key === key);
  return f && "secret" in f ? f.secret : null;
};
const kept = (s: SecretInput | null) => !!s && !("clear" in s);

/// The item a draft makes of what was there (or of nothing, for a new one).
/// The page's second line is worked out the way a sync would.
export function itemOf(d: ItemDraft, base: Item): Item {
  const last4 = (() => {
    const n = fieldSecret(d, "number");
    if (n && "set" in n) return /(\d{4})\s*$/.exec(n.set)?.[1] ?? null;
    return /(\d{4})$/.exec(base.subtitle ?? "")?.[1] ?? null;
  })();
  const brand = fieldValue(d, "brand");
  const subtitle =
    d.kind === ItemKind.Login
      ? fieldValue(d, "username") || null
      : d.kind === ItemKind.Card
        ? [brand, last4 ? `·· ${last4}` : null].filter(Boolean).join(" ") || null
        : d.kind === ItemKind.Identity
          ? fieldValue(d, "email") || null
          : d.kind === ItemKind.SshKey
            ? base.subtitle
            : null;
  const month = fieldValue(d, "expMonth");
  const year = fieldValue(d, "expYear");
  return {
    ...base,
    name: d.name,
    kind: d.kind,
    subtitle,
    folderId: d.folderId,
    orgId: d.orgId,
    collectionIds: [...d.collectionIds],
    uris: [...d.uris],
    tags: { ...d.tags },
    hasTotp: kept(fieldSecret(d, "totp")),
    favorite: d.favorite,
    reprompt: d.reprompt,
    expires: d.kind === ItemKind.Card && month && year ? `${year.length === 2 ? `20${year}` : year}-${month.padStart(2, "0")}` : d.kind === ItemKind.Card ? null : base.expires,
  };
}

/// The opened item a draft makes: fields in the page's vocabulary, every
/// secret a reference. What a saved draft reads like before the backend
/// answers, and what the demo answers.
export function detailOf(d: ItemDraft, item: Item, prev: ItemDetail | null): ItemDetail {
  const id = item.id;
  const fields: Field[] = [];
  const ref = (field: Exclude<SecretField, SecretField.Custom>): SecretRef => ({ itemId: id, field });
  const vis = (key: string, value: string | null, mono = false, secret: SecretRef | null = null) => {
    if (value) fields.push({ key, label: key, value, secret, mono });
  };
  const hid = (key: string, s: SecretInput | null, r: SecretRef) => {
    if (kept(s)) fields.push({ key, label: key, value: null, secret: r, mono: true });
  };
  const v = (k: string) => fieldValue(d, k);
  const s = (k: string) => fieldSecret(d, k);
  if (d.kind === ItemKind.Login) {
    vis("username", v("username"), true, ref(SecretField.Username));
    hid("password", s("password"), ref(SecretField.Password));
    hid("totp", s("totp"), ref(SecretField.Totp));
  } else if (d.kind === ItemKind.Card) {
    vis("cardholder", v("cardholderName"));
    vis("brand", v("brand"));
    hid("cardNumber", s("number"), ref(SecretField.CardNumber));
    const m = v("expMonth");
    const y = v("expYear");
    if (m && y) vis("expiry", `${m.padStart(2, "0")} / ${y.length === 2 ? `20${y}` : y}`, true);
    hid("cardCode", s("code"), ref(SecretField.CardCode));
  } else if (d.kind === ItemKind.Identity) {
    vis("fullName", [v("firstName"), v("lastName")].filter(Boolean).join(" "));
    vis("email", v("email"), true);
    vis("phone", v("phone"), true);
    vis("company", v("company"));
  } else if (d.kind === ItemKind.SshKey) {
    const alg = prev?.fields.find((f) => f.key === "algorithm");
    if (alg) fields.push(alg);
    vis("fingerprint", v("fingerprint"), true);
    vis("publicKey", v("publicKey"), true);
    hid("privateKey", s("privateKey"), ref(SecretField.PrivateKey));
  }
  for (const f of d.fields) {
    if (!("custom" in f)) continue;
    const r: SecretRef = { itemId: id, field: SecretField.Custom, name: f.custom };
    if (!f.hidden) fields.push({ key: null, label: f.custom, value: f.value, secret: r, mono: prev?.fields.find((x) => x.key === null && x.label === f.custom)?.mono ?? false });
    else if (kept(f.secret)) fields.push({ key: null, label: f.custom, value: null, secret: r, mono: true });
  }
  return { item, fields, notes: kept(d.notes) ? ref(SecretField.Notes) : null, passkeys: prev?.passkeys ?? [], passwordHistory: prev?.passwordHistory ?? [] };
}

/// The generator's first options: a long password of every set.
export const DEFAULT_GENERATOR: { password: Extract<GeneratorOptions, { kind: GeneratorKind.Password }>; passphrase: Extract<GeneratorOptions, { kind: GeneratorKind.Passphrase }> } = {
  password: { kind: GeneratorKind.Password, length: 20, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguous: false },
  passphrase: { kind: GeneratorKind.Passphrase, words: 4, separator: "-", capitalize: true, number: true },
};
