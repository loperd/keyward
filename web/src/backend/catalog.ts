// The catalogue and an item's card, built in the tab from the encrypted
// snapshot — the shapes of ui/core, the reading of crates/vault/src/read.rs.
//
// Decrypted here is only what a list or a card shows: names, logins, hosts,
// fingerprints, folders and collections, a card's brand, last four digits
// and expiry. A password is decrypted once per build for reuse detection and
// only as bytes: salted, hashed, wiped. Card numbers are read as bytes for
// their last four and their network, then wiped. Codes, TOTP seeds, notes,
// private keys and hidden fields are not touched — they are opened by
// `secretBytes` alone, inside a copy, a reveal or a code.
import { type Catalog, type Collection, type Field, type Folder, type Item, type ItemDetail, ItemKind, type Member, MemberStatus, type Org, type OrgAbilities, OrgRole, Permission, type SecretRef, SecretField } from "@keyward/core/model/types";
import { fromUtf8, zero, type Bytes } from "./bytes";
import { randomBytes, sha256, type SymKey } from "./crypto";
import { decryptBytes, decryptString } from "./encstring";
import { fail } from "./errors";
import type { KeyRing } from "./keys";
import { inTrash, type SyncCipher, type SyncData, type SyncOrg } from "./sync";

/// keyward's own service items carry this field and stay out of the list.
export const HIDDEN_MARK = "kw-hidden";
const FIELD_PREFIX = "kw-";

const FIELD_TEXT = 0;
const FIELD_HIDDEN = 1;
const FIELD_BOOLEAN = 2;
const FIELD_LINKED = 3;

export function kindOf(c: SyncCipher): ItemKind {
  switch (c.type) {
    case 1:
      return ItemKind.Login;
    case 2:
      return ItemKind.SecureNote;
    case 3:
      return ItemKind.Card;
    case 4:
      return ItemKind.Identity;
    case 5:
      return ItemKind.SshKey;
  }
  // A type newer than this client: not corrupt data, so it is shown by what
  // it carries, as the daemon shows it, and its secrets stay where they are.
  if (c.card) return ItemKind.Card;
  if (c.identity) return ItemKind.Identity;
  if (c.sshKey) return ItemKind.SshKey;
  if (c.login) return ItemKind.Login;
  return ItemKind.SecureNote;
}

export function roleOf(code: number): OrgRole {
  switch (code) {
    case 0:
      return OrgRole.Owner;
    case 1:
      return OrgRole.Admin;
    case 2:
      return OrgRole.User;
    case 3:
      return OrgRole.Manager;
    case 4:
      return OrgRole.Custom;
  }
  // A role in no documentation is trusted with nothing — and not shown as a
  // role it is not.
  return fail("err.unknownOrgRole", { code });
}

/// One's abilities in an organisation, worked out as a Bitwarden client does
/// (crates/core/src/items.rs `OrgRights`): the fixed roles carry their rights,
/// a custom role carries its permissions.
export function abilitiesOf(o: SyncOrg): OrgAbilities {
  const role = roleOf(o.type);
  const admin = role === OrgRole.Owner || role === OrgRole.Admin;
  const custom = (granted: boolean) => role === OrgRole.Custom && granted;
  const p = o.permissions;
  return {
    editOrg: role === OrgRole.Owner,
    manageMembers: admin || custom(p.manageUsers),
    manageCollections: admin || custom(p.createNewCollections || p.editAnyCollection || p.deleteAnyCollection),
  };
}

const statusOf = (code: number): MemberStatus => {
  switch (code) {
    case -1:
      return MemberStatus.Revoked;
    case 0:
      return MemberStatus.Invited;
    case 1:
      return MemberStatus.Accepted;
    case 2:
      return MemberStatus.Confirmed;
  }
  return fail("err.unknownMemberStatus", { code });
};

/// The IIN is enough to name a network; the number itself never leaves this
/// function as text.
export function cardNetwork(digits: Bytes): string | null {
  const d = (n: number) => (n <= digits.length ? String.fromCharCode(...digits.subarray(0, n)) : "");
  const p2 = Number(d(2));
  const p3 = d(3);
  const p4 = Number(d(4));
  if (d(1) === "4") return "Visa";
  if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return "Mastercard";
  if (p2 === 34 || p2 === 37) return "American Express";
  if (d(4) === "6011" || d(2) === "65" || ["644", "645", "646", "647", "648", "649"].includes(p3)) return "Discover";
  if (d(4) === "2131" || d(4) === "1800" || d(2) === "35") return "JCB";
  if (p2 === 30 || p2 === 36 || p2 === 38) return "Diners Club";
  if (d(2) === "62") return "UnionPay";
  return null;
}

/// A card number's digits, its last four and its network, read from its bytes
/// and wiped.
async function cardFacts(value: string, key: SymKey): Promise<{ last4: string | null; network: string | null }> {
  const bytes = await decryptBytes(value, key);
  let digits = new Uint8Array(0);
  try {
    digits = bytes.filter((b) => b >= 0x30 && b <= 0x39);
    const last4 = digits.length >= 4 ? String.fromCharCode(...digits.subarray(digits.length - 4)) : null;
    return { last4, network: cardNetwork(digits) };
  } finally {
    zero(bytes, digits);
  }
}

const dec = (v: string | null, key: SymKey): Promise<string | null> => (v === null ? Promise.resolve(null) : decryptString(v, key));

/// A field's decrypted name, trimmed.
async function fieldName(f: { name: string | null }, key: SymKey): Promise<string | null> {
  const n = await dec(f.name, key);
  return n === null ? null : n.trim();
}

async function isHidden(c: SyncCipher, key: SymKey): Promise<boolean> {
  for (const f of c.fields) {
    const n = await fieldName(f, key);
    if (n !== null && n.toLowerCase() === HIDDEN_MARK) return true;
  }
  return false;
}

/// The item's own `kw-*` fields. A hidden one's value is a secret like any
/// other and is not carried: the web app has no plugin to hand it to.
async function tagsOf(c: SyncCipher, key: SymKey): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const f of c.fields) {
    if (f.type === FIELD_HIDDEN) continue;
    const n = await fieldName(f, key);
    if (n === null) continue;
    const name = n.toLowerCase();
    if (!name.startsWith(FIELD_PREFIX)) continue;
    out[name] = (await dec(f.value, key)) ?? "";
  }
  return out;
}

function expiry(month: string | null, year: string | null): string | null {
  if (month === null || year === null) return null;
  const m = month.trim();
  const y = year.trim();
  if (!/^\d{1,2}$/.test(m) || !/^\d{2,4}$/.test(y)) return null;
  const mm = Number(m);
  let yy = Number(y);
  if (yy < 100) yy += 2000;
  if (mm < 1 || mm > 12) return null;
  return `${String(yy).padStart(4, "0")}-${String(mm).padStart(2, "0")}`;
}

/// The quiet second line, as the desktop shows it.
async function subtitleOf(c: SyncCipher, kind: ItemKind, key: SymKey, card: { brand: string | null; last4: string | null }) {
  switch (kind) {
    case ItemKind.Login:
      return dec(c.login?.username ?? null, key);
    case ItemKind.Card:
      if (card.brand && card.last4) return `${card.brand} ·· ${card.last4}`;
      return card.brand ?? (card.last4 ? `·· ${card.last4}` : null);
    case ItemKind.Identity:
      return dec(c.identity?.email ?? c.identity?.username ?? null, key);
    case ItemKind.SshKey:
      return dec(c.sshKey?.fingerprint ?? null, key);
    case ItemKind.SecureNote:
      return null;
  }
}

/// One list row, and the password's salted hash for reuse detection (the
/// hash goes no further than `buildCatalog`).
async function itemOf(c: SyncCipher, ring: KeyRing, salt: Bytes): Promise<{ item: Item; hash: Bytes | null } | null> {
  const key = await ring.forItem(c);
  if (await isHidden(c, key)) return null;
  const kind = kindOf(c);

  let brand: string | null = null;
  let last4: string | null = null;
  let expires: string | null = null;
  if (c.card) {
    const b = await dec(c.card.brand, key);
    const facts = c.card.number !== null ? await cardFacts(c.card.number, key) : { last4: null, network: null };
    brand = b !== null && b.trim() !== "" && b.toLowerCase() !== "other" ? b : facts.network;
    last4 = facts.last4;
    expires = expiry(await dec(c.card.expMonth, key), await dec(c.card.expYear, key));
  }

  // The password once, as bytes: salted with this build's salt, hashed,
  // wiped. Only the digest lives on, and only until the counts are made.
  let hash: Bytes | null = null;
  if (!inTrash(c) && c.login?.password) {
    const pw = await decryptBytes(c.login.password, key);
    try {
      if (pw.length > 0) hash = await sha256(salt, pw);
    } finally {
      zero(pw);
    }
  }

  const uris: string[] = [];
  for (const u of c.login?.uris ?? []) uris.push(await decryptString(u, key));

  const item: Item = {
    id: c.id,
    name: await decryptString(c.name, key),
    kind,
    subtitle: await subtitleOf(c, kind, key, { brand, last4 }),
    folderId: c.folderId,
    orgId: c.organizationId,
    collectionIds: c.collectionIds,
    uris,
    tags: await tagsOf(c, key),
    hasTotp: c.login?.totp != null && c.login.totp !== "",
    passkeys: c.login?.passkeys.length ?? 0,
    favorite: c.favorite,
    deleted: inTrash(c),
    reprompt: c.reprompt !== 0,
    revised: c.revisionDate,
    passwordRevised: c.login?.passwordRevisionDate ?? null,
    expires,
    reused: 0,
    reuseGroup: null,
  };
  return { item, hash };
}

const hex = (b: Bytes) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/// The whole catalogue. Members come only for organisations where one may
/// manage them (fetched by the caller); for the rest, none.
export async function buildCatalog(snapshot: SyncData, ring: KeyRing, members: Member[]): Promise<Catalog> {
  const folders: Folder[] = [];
  for (const f of snapshot.folders) folders.push({ id: f.id, name: await decryptString(f.name, ring.userKey()) });

  const orgs: Org[] = snapshot.profile.organizations.map((o) => ({ id: o.id, name: o.name, role: roleOf(o.type), can: abilitiesOf(o) }));

  const collections: Collection[] = [];
  for (const c of snapshot.collections) {
    collections.push({ id: c.id, orgId: c.organizationId, name: await decryptString(c.name, ring.base(c.organizationId)), readOnly: c.readOnly });
  }

  // A fresh salt per build: a digest is of no use outside this one build,
  // and neither it nor the password reaches the window.
  const salt = randomBytes(32);
  const hashes = new Map<number, string>();
  const items: Item[] = [];
  try {
    for (const c of snapshot.ciphers) {
      const row = await itemOf(c, ring, salt);
      if (!row) continue;
      if (row.hash) {
        hashes.set(items.length, hex(row.hash));
        zero(row.hash);
      }
      items.push(row.item);
    }
    const counts = new Map<string, number>();
    for (const h of hashes.values()) counts.set(h, (counts.get(h) ?? 0) + 1);
    const groups = new Map<string, number>();
    for (const [index, h] of hashes) {
      const same = counts.get(h)!;
      const item = items[index]!;
      item.reused = same - 1;
      if (same > 1) {
        if (!groups.has(h)) groups.set(h, groups.size);
        item.reuseGroup = groups.get(h)!;
      }
    }
  } finally {
    zero(salt);
    hashes.clear();
  }

  items.sort((a, b) => {
    const x = a.name.toLowerCase();
    const y = b.name.toLowerCase();
    return x < y ? -1 : x > y ? 1 : 0;
  });
  return { items, folders, orgs, collections, members };
}

/// Members of an organisation, from `/api/organizations/{id}/users`.
export function membersOf(orgId: string, body: string, myEmail: string): Member[] {
  let v: unknown;
  try {
    v = JSON.parse(body);
  } catch {
    return fail("err.syncUnreadable", { reason: "members" });
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) return fail("err.syncUnreadable", { reason: "members" });
  const o = v as Record<string, unknown>;
  const data = o.data ?? o.Data ?? [];
  if (!Array.isArray(data)) return fail("err.syncUnreadable", { reason: "members.data" });
  return data.map((raw, i) => {
    if (typeof raw !== "object" || raw === null) return fail("err.syncUnreadable", { reason: `members[${i}]` });
    const u = raw as Record<string, unknown>;
    const str = (k: string) => (typeof u[k] === "string" ? (u[k] as string) : null);
    const int = (k: string, absent: number) => {
      const x = u[k];
      if (x === undefined || x === null) return absent;
      if (typeof x !== "number" || !Number.isInteger(x)) return fail("err.syncUnreadable", { reason: `members[${i}].${k}` });
      return x;
    };
    const id = str("id") ?? fail("err.syncUnreadable", { reason: `members[${i}].id` });
    const email = str("email") ?? fail("err.syncUnreadable", { reason: `members[${i}].email` });
    const name = str("name");
    const access: Record<string, Permission> = {};
    const cols = u.collections ?? [];
    if (!Array.isArray(cols)) return fail("err.syncUnreadable", { reason: `members[${i}].collections` });
    for (const col of cols) {
      if (typeof col !== "object" || col === null) return fail("err.syncUnreadable", { reason: `members[${i}].collections` });
      const cr = col as Record<string, unknown>;
      if (typeof cr.id !== "string") return fail("err.syncUnreadable", { reason: `members[${i}].collections.id` });
      access[cr.id] = permissionOf(cr.readOnly === true, cr.hidePasswords === true, cr.manage === true);
    }
    const accessAll = u.accessAll === true;
    return {
      id,
      orgId,
      // A name that only repeats the email is shown once.
      name: name !== null && name.trim() !== "" && name.toLowerCase() !== email.toLowerCase() ? name : null,
      email,
      role: roleOf(int("type", -1)),
      status: statusOf(int("status", -99)),
      twoFactor: typeof u.twoFactorEnabled === "boolean" ? u.twoFactorEnabled : null,
      accessAll,
      access: accessAll ? {} : access,
      isYou: email.toLowerCase() === myEmail.toLowerCase(),
    };
  });
}

/// A collection grant in the window's words; `manage` outranks the other two
/// flags, as on the server.
export function permissionOf(readOnly: boolean, hidePasswords: boolean, manage: boolean): Permission {
  if (manage) return Permission.Manage;
  if (hidePasswords) return readOnly ? Permission.ReadHidden : Permission.EditHidden;
  return readOnly ? Permission.Read : Permission.Edit;
}

const visible = (key: string, value: string | null, mono = false): Field | null =>
  value === null || value.trim() === "" ? null : { key, label: key, value, secret: null, mono };

const secret = (key: string, ref: SecretRef, mono = true): Field => ({ key, label: key, value: null, secret: ref, mono });

/// An item's card. Secret fields carry no value — only the name to ask for it
/// by, through `copy`, `reveal` or `totp`.
export async function buildDetail(snapshot: SyncData, ring: KeyRing, id: string, item: Item): Promise<ItemDetail> {
  const c = findCipher(snapshot, id);
  const key = await ring.forItem(c);
  const fields: Field[] = [];
  const push = (f: Field | null) => {
    if (f) fields.push(f);
  };

  switch (kindOf(c)) {
    case ItemKind.Login: {
      const l = c.login;
      if (!l) break;
      const user = await dec(l.username, key);
      if (user !== null && user !== "") {
        fields.push({ key: "username", label: "username", value: user, secret: { itemId: id, field: SecretField.Username }, mono: false });
      }
      if (l.password !== null) fields.push(secret("password", { itemId: id, field: SecretField.Password }));
      if (l.totp !== null) fields.push(secret("totp", { itemId: id, field: SecretField.Totp }));
      break;
    }
    case ItemKind.Card: {
      const k = c.card;
      if (!k) break;
      push(visible("cardholder", await dec(k.cardholderName, key)));
      push(visible("brand", await dec(k.brand, key)));
      const exp = expiry(await dec(k.expMonth, key), await dec(k.expYear, key));
      if (exp) push(visible("expiry", `${exp.slice(5)}/${exp.slice(0, 4)}`, true));
      if (k.number !== null) fields.push(secret("cardNumber", { itemId: id, field: SecretField.CardNumber }));
      if (k.code !== null) fields.push(secret("cardCode", { itemId: id, field: SecretField.CardCode }));
      break;
    }
    case ItemKind.Identity: {
      const i = c.identity;
      if (!i) break;
      const first = await dec(i.firstName, key);
      const last = await dec(i.lastName, key);
      push(visible("fullName", [first, last].filter((x) => x !== null && x.trim() !== "").join(" ")));
      push(visible("email", await dec(i.email, key)));
      push(visible("phone", await dec(i.phone, key)));
      break;
    }
    case ItemKind.SshKey: {
      const s = c.sshKey;
      if (!s) break;
      push(visible("fingerprint", await dec(s.fingerprint, key), true));
      push(visible("publicKey", await dec(s.publicKey, key), true));
      if (s.privateKey !== null) fields.push(secret("privateKey", { itemId: id, field: SecretField.PrivateKey }));
      break;
    }
    case ItemKind.SecureNote:
      break;
  }

  for (const f of c.fields) {
    const name = await fieldName(f, key);
    if (name === null || name.toLowerCase().startsWith(FIELD_PREFIX)) continue;
    switch (f.type) {
      case FIELD_BOOLEAN: {
        const v = await dec(f.value, key);
        fields.push({ key: "checkbox", label: name, value: v !== null && v.trim().toLowerCase() === "true" ? "true" : "false", secret: null, mono: false });
        break;
      }
      case FIELD_LINKED:
        // A linked field has no value of its own, only the number of the
        // field it points at; the window names it from the key.
        fields.push({ key: f.linkedId === null ? "link:none" : `link:${f.linkedId}`, label: name, value: null, secret: null, mono: false });
        break;
      case FIELD_HIDDEN:
        fields.push({ key: null, label: name, value: null, secret: { itemId: id, field: SecretField.Custom, name }, mono: true });
        break;
      case FIELD_TEXT: {
        const v = await dec(f.value, key);
        if (v === null || v.trim() === "") break;
        fields.push({ key: null, label: name, value: v, secret: { itemId: id, field: SecretField.Custom, name }, mono: false });
        break;
      }
      default:
        // A field type newer than this client: its value may be anything,
        // so it is treated as a secret.
        fields.push({ key: null, label: name, value: null, secret: { itemId: id, field: SecretField.Custom, name }, mono: true });
    }
  }

  const passkeys: ItemDetail["passkeys"] = [];
  for (const p of c.login?.passkeys ?? []) {
    // Every passkey field is an EncString of its own; the private key
    // (`keyValue`) is never opened.
    const rp = typeof p.rpId === "string" ? await decryptString(p.rpId, key) : null;
    if (rp === null) fail("err.syncUnreadable", { reason: "passkey.rpId" });
    const userName = typeof p.userName === "string" ? await decryptString(p.userName, key) : null;
    passkeys.push({ rpId: rp!, userName: userName === "" ? null : userName });
  }

  const passwordHistory = c.passwordHistory
    .filter((h) => h.password !== null && h.password !== "")
    .map((h) => ({ changed: h.lastUsedDate ?? fail("err.syncUnreadable", { reason: "passwordHistory.lastUsedDate" }) }));

  return { item, fields, notes: c.notes !== null ? { itemId: id, field: SecretField.Notes } : null, passkeys, passwordHistory };
}

export function findCipher(snapshot: SyncData, id: string): SyncCipher {
  // Duplicate ids are possible from a server that misbehaves; the first one
  // is taken everywhere, so a copy and the list never disagree.
  return snapshot.ciphers.find((c) => c.id === id) ?? fail("err.itemNotFound");
}

/// A secret's bytes, opened for one use. The caller wipes them.
export async function secretBytes(snapshot: SyncData, ring: KeyRing, ref: SecretRef): Promise<Bytes> {
  const c = findCipher(snapshot, ref.itemId);
  const key = await ring.forItem(c);
  const sealed = await sealedOf(c, ref, key);
  if (sealed === null) return fail("err.secretAbsent");
  return decryptBytes(sealed, key);
}

async function sealedOf(c: SyncCipher, ref: SecretRef, key: SymKey): Promise<string | null> {
  switch (ref.field) {
    case SecretField.Password:
      return c.login?.password ?? null;
    case SecretField.Username:
      return c.login?.username ?? null;
    case SecretField.Totp:
      return c.login?.totp ?? null;
    case SecretField.CardNumber:
      return c.card?.number ?? null;
    case SecretField.CardCode:
      return c.card?.code ?? null;
    case SecretField.Notes:
      return c.notes;
    case SecretField.PrivateKey:
      return c.sshKey?.privateKey ?? null;
    case SecretField.Custom: {
      // By name, the first match, as the daemon finds it. The window only
      // asks by names this card gave it.
      const wanted = ref.name.trim();
      for (const f of c.fields) {
        if (f.type === FIELD_BOOLEAN || f.type === FIELD_LINKED) continue;
        if ((await fieldName(f, key)) === wanted) return f.value;
      }
      return null;
    }
  }
}

/// A secret as text, for the clipboard or the screen. Strings cannot be
/// wiped; this one is the caller's to drop as soon as it has served.
export async function secretText(snapshot: SyncData, ring: KeyRing, ref: SecretRef): Promise<string> {
  const bytes = await secretBytes(snapshot, ring, ref);
  try {
    return fromUtf8(bytes);
  } finally {
    zero(bytes);
  }
}

