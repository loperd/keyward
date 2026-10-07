// The web app's writes: the `Writes` of ui/core, answered from the tab with
// the KeyRing's keys and the server's endpoints, as crates/bw and
// crates/vault speak them.
//
// Where the secrets are:
//   - A value a person typed arrives in a draft as text, is encoded to bytes,
//     sealed (`2.iv|ct|mac`) and the bytes wiped (encrypt.ts); only the
//     ciphertext goes on.
//   - A value already stored is named by `keep` and sent back as the very
//     EncString the server holds: it is never decrypted to be re-encrypted.
//   - The item is read fresh from the server before an edit, so every part
//     this app does not show (an identity's address, passkeys, password
//     history, an item's own key, linked fields, hidden `kw-*` fields) goes
//     back exactly as it was: the server replaces an item whole.
//   - A confirm opens an organisation key's bytes for the moment it is sealed
//     for the member, then wipes them.
//   - The password check derives the hash locally and compares it with a
//     digest of the login's, held in memory only; the password never leaves.
// After every write the encrypted snapshot is synced again and the change
// said, so the window rebases on what the server now holds.
import { type Change, ChangeKind } from "@keyward/core/backend";
import { type Catalog, ItemKind, OrgRole, Permission } from "@keyward/core/model/types";
import { type DraftField, type GeneratorOptions, type Invite, type ItemDraft, type MergeComparison, type MergePlan, type MergeRow, type MergeSlot, type SecretInput, type Writes, GeneratorKind, MergeField } from "@keyward/core/writes";
import { planRefusal, slotKey } from "@keyward/core/edit/merge";
import { isPathId } from "./api";
import { constantTimeEqual, fromB64, toB64, utf8, zero, type Bytes } from "./bytes";
import { abilitiesOf } from "./catalog";
import { sha256, type SymKey } from "./crypto";
import { decryptString, parseEncString, unwrapSymKey } from "./encstring";
import { encryptText, importMemberPublicKey, sealForMember } from "./encrypt";
import { fail } from "./errors";
import { deriveMasterKey, masterPasswordHash, type Kdf } from "./kdf";
import type { KeyRing } from "./keys";
import type { SyncData, SyncOrg } from "./sync";
import wordlist from "./eff_large_wordlist.json";

/// What the writes need of the backend that holds the session.
export type WriteHost = {
  /// The keys and the snapshot of an unlocked session; `err.locked` else.
  open(): { ring: KeyRing; snapshot: SyncData };
  /// The window's catalogue: only what it lists may be written to.
  catalog(): Promise<Catalog>;
  authed(method: string, path: string, json?: unknown): Promise<string>;
  /// Syncs the snapshot again and says `{ kind: "catalog" }`.
  sync(): Promise<void>;
  account(): { email: string; kdf: Kdf };
  emit(c: Change): void;
  now(): number;
};

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/// Every key in camelCase, deep: the servers answer in either casing, and an
/// item goes back in the one Bitwarden documents.
function camel(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(camel);
  if (!isObj(v)) return v;
  const out: Obj = {};
  for (const [k, x] of Object.entries(v)) out[k.length ? k[0]!.toLowerCase() + k.slice(1) : k] = camel(x);
  return out;
}

const unreadable = (reason: string): never => fail("err.writeAnswerUnreadable", { reason });

function answer(body: string, where: string): Obj {
  let v: unknown;
  try {
    v = JSON.parse(body);
  } catch {
    return unreadable(where);
  }
  const o = camel(v);
  return isObj(o) ? o : unreadable(where);
}

function idOf(o: Obj, where: string): string {
  const id = o.id;
  if (typeof id !== "string" || !isPathId(id)) return unreadable(`${where}.id`);
  return id;
}

const pathId = (id: string): string => (isPathId(id) ? id : fail("err.badIdentifier"));

/// A stored value as the server sent it: an EncString, or absent. Its shape
/// is checked (never its contents: it is not opened).
function stored(v: unknown, where: string): string | null {
  if (v === undefined || v === null) return null;
  if (typeof v !== "string") return unreadable(where);
  if (v === "") return null;
  parseEncString(v);
  return v;
}

// --- item kinds and their built-in fields ------------------------------------

const KIND_CODE: Record<ItemKind, number> = { [ItemKind.Login]: 1, [ItemKind.SecureNote]: 2, [ItemKind.Card]: 3, [ItemKind.Identity]: 4, [ItemKind.SshKey]: 5 };

/// Each kind's part of the item on the wire and its draft keys → wire names.
const PARTS: Record<ItemKind, { part: string; keys: Record<string, string> }> = {
  [ItemKind.Login]: { part: "login", keys: { username: "username", password: "password", totp: "totp" } },
  [ItemKind.SecureNote]: { part: "secureNote", keys: {} },
  [ItemKind.Card]: {
    part: "card",
    keys: { cardholderName: "cardholderName", brand: "brand", number: "number", expMonth: "expMonth", expYear: "expYear", code: "code" },
  },
  [ItemKind.Identity]: {
    part: "identity",
    keys: Object.fromEntries(
      [
        "title",
        "firstName",
        "middleName",
        "lastName",
        "address1",
        "address2",
        "address3",
        "city",
        "state",
        "postalCode",
        "country",
        "company",
        "email",
        "phone",
        "ssn",
        "username",
        "passportNumber",
        "licenseNumber",
      ].map((k) => [k, k]),
    ),
  },
  // The fingerprint is `keyFingerprint` on the wire (crates/bw/src/model.rs).
  [ItemKind.SshKey]: { part: "sshKey", keys: { privateKey: "privateKey", publicKey: "publicKey", fingerprint: "keyFingerprint" } },
};

function kindCode(kind: ItemKind): number {
  return Object.prototype.hasOwnProperty.call(KIND_CODE, kind) ? KIND_CODE[kind] : fail("err.itemKindUnknown", { kind: String(kind) });
}

const FIELD_TEXT = 0;
const FIELD_HIDDEN = 1;
const FIELD_BOOLEAN = 2;
const FIELD_LINKED = 3;
const TAG_PREFIX = "kw-";
/// Bitwarden keeps this many old passwords.
const HISTORY_MAX = 5;

const ROLE_CODE: Record<Exclude<OrgRole, OrgRole.Custom>, number> = { [OrgRole.Owner]: 0, [OrgRole.Admin]: 1, [OrgRole.User]: 2, [OrgRole.Manager]: 3 };

function roleCode(role: OrgRole): number {
  if (role === OrgRole.Custom) return fail("err.customRoleUnsupported");
  return Object.prototype.hasOwnProperty.call(ROLE_CODE, role) ? ROLE_CODE[role] : fail("err.unknownOrgRole", { code: String(role) });
}

/// A grant in the server's flags: the reverse of `permissionOf`.
function grantOf(p: Permission): { readOnly: boolean; hidePasswords: boolean; manage: boolean } {
  switch (p) {
    case Permission.Manage:
      return { readOnly: false, hidePasswords: false, manage: true };
    case Permission.Edit:
      return { readOnly: false, hidePasswords: false, manage: false };
    case Permission.EditHidden:
      return { readOnly: false, hidePasswords: true, manage: false };
    case Permission.Read:
      return { readOnly: true, hidePasswords: false, manage: false };
    case Permission.ReadHidden:
      return { readOnly: true, hidePasswords: true, manage: false };
  }
  return fail("err.permissionUnknown", { permission: String(p) });
}

// --- the generator ------------------------------------------------------------

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
/// Bitwarden's set: what every site's password rules accept.
const SYMBOLS = "!@#$%^&*";
/// Characters a person misreads: I/l/1, O/0.
const AMBIGUOUS = "IOl01";

export const PASSWORD_LENGTH = { min: 5, max: 128 } as const;
export const PASSPHRASE_WORDS = { min: 3, max: 20 } as const;

/// An unbiased integer in `[0, n)`: a 32-bit draw outside the largest
/// multiple of `n` is thrown away and drawn again, so no value is likelier
/// than another (`x % n` alone favours the small ones).
export function randomBelow(n: number): number {
  if (!Number.isInteger(n) || n < 1 || n > 2 ** 32) fail("err.generatorRange");
  const limit = 2 ** 32 - (2 ** 32 % n);
  const draw = new Uint32Array(1);
  try {
    for (;;) {
      globalThis.crypto.getRandomValues(draw);
      if (draw[0]! < limit) return draw[0]! % n;
    }
  } finally {
    draw.fill(0);
  }
}

let words: readonly string[] | null = null;

/// The EFF long list, checked once: 7776 distinct words. Anything else is a
/// broken build, and a passphrase from it would be weaker than it says.
function wordList(): readonly string[] {
  if (words) return words;
  const list = (wordlist as { words?: unknown }).words;
  if (!Array.isArray(list) || list.length !== 7776 || new Set(list).size !== 7776 || !list.every((w) => typeof w === "string" && /^[a-z-]+$/.test(w))) {
    return fail("err.wordlistCorrupt");
  }
  words = list as string[];
  return words;
}

/// Bitwarden's fingerprint phrase for a user's public key (the clients'
/// `fingerprint`, crates/vault/src/fingerprint.rs): `HKDF-Expand(prk =
/// SHA-256(SPKI DER), info = userId, 32 bytes)` read as one big-endian number
/// and written out in base 7776, five digits, lowest first, each a word of the
/// EFF long list. One block of output is a single HMAC over `info || 0x01`;
/// WebCrypto's HKDF would run Extract first, so the block is computed directly.
export async function fingerprintPhrase(userId: string, spkiDer: Bytes): Promise<string[]> {
  const list = wordList();
  const prk = await globalThis.crypto.subtle.importKey("raw", await sha256(spkiDer), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const info = utf8(userId);
  const block = new Uint8Array(info.length + 1);
  block.set(info, 0);
  block[info.length] = 1;
  const okm = new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", prk, block));
  let n = 0n;
  for (const b of okm) n = (n << 8n) | BigInt(b);
  const base = BigInt(list.length);
  const out: string[] = [];
  for (let i = 0; i < 5; i++) {
    out.push(list[Number(n % base)]!);
    n /= base;
  }
  return out;
}

function shown(value: string): { value: string; drop: () => void } {
  const out = {
    value,
    drop: () => {
      out.value = "";
    },
  };
  return out;
}

function password(o: Extract<GeneratorOptions, { kind: GeneratorKind.Password }>): string {
  if (!Number.isInteger(o.length) || o.length < PASSWORD_LENGTH.min || o.length > PASSWORD_LENGTH.max) {
    fail("err.generatorLength", { min: PASSWORD_LENGTH.min, max: PASSWORD_LENGTH.max });
  }
  const strip = (s: string) => (o.avoidAmbiguous ? [...s].filter((c) => !AMBIGUOUS.includes(c)).join("") : s);
  const sets = [o.upper && strip(UPPER), o.lower && strip(LOWER), o.digits && strip(DIGITS), o.symbols && SYMBOLS].filter(
    (s): s is string => typeof s === "string" && s !== "",
  );
  if (sets.length === 0) fail("err.generatorNoCharset");
  if (o.length < sets.length) fail("err.generatorLength", { min: Math.max(sets.length, PASSWORD_LENGTH.min), max: PASSWORD_LENGTH.max });
  const all = sets.join("");
  const codes = new Uint16Array(o.length);
  try {
    // One of each chosen set, so the rules a person ticked hold; the rest
    // from all of them; then shuffled (Fisher–Yates, unbiased draws), so
    // the guaranteed ones sit nowhere in particular.
    sets.forEach((s, i) => {
      codes[i] = s.charCodeAt(randomBelow(s.length));
    });
    for (let i = sets.length; i < o.length; i++) codes[i] = all.charCodeAt(randomBelow(all.length));
    for (let i = codes.length - 1; i > 0; i--) {
      const j = randomBelow(i + 1);
      const t = codes[i]!;
      codes[i] = codes[j]!;
      codes[j] = t;
    }
    return String.fromCharCode(...codes);
  } finally {
    codes.fill(0);
  }
}

function passphrase(o: Extract<GeneratorOptions, { kind: GeneratorKind.Passphrase }>): string {
  if (!Number.isInteger(o.words) || o.words < PASSPHRASE_WORDS.min || o.words > PASSPHRASE_WORDS.max) {
    fail("err.generatorWords", { min: PASSPHRASE_WORDS.min, max: PASSPHRASE_WORDS.max });
  }
  if (typeof o.separator !== "string" || [...o.separator].length > 1 || /[\p{L}\p{N}]/u.test(o.separator)) {
    // A letter or a digit would blur where one word ends; more than one
    // character is not what any client offers.
    fail("err.generatorSeparator");
  }
  const list = wordList();
  const picked: string[] = [];
  for (let i = 0; i < o.words; i++) {
    const w = list[randomBelow(list.length)]!;
    picked.push(o.capitalize ? w[0]!.toUpperCase() + w.slice(1) : w);
  }
  // As Bitwarden does: one digit, on the end of one word.
  if (o.number) {
    const at = randomBelow(picked.length);
    picked[at] = picked[at]! + String(randomBelow(10));
  }
  try {
    return picked.join(o.separator);
  } finally {
    picked.fill("");
  }
}

// --- the item's body ------------------------------------------------------------

/// A draft value into an EncString: empty is no value.
const seal = (key: SymKey, v: string | null): Promise<string | null> =>
  v === null || v === "" ? Promise.resolve(null) : encryptText(key, v);

/// A secret's new form: typed (sealed), cleared, or the stored EncString
/// itself. A new item has nothing stored to keep.
async function secretValue(key: SymKey, input: SecretInput, old: unknown, where: string, isNew: boolean): Promise<string | null> {
  if (!isObj(input)) return fail("err.draftSecretMalformed", { where });
  if ("set" in input) {
    if (typeof input.set !== "string") return fail("err.draftSecretMalformed", { where });
    return seal(key, input.set);
  }
  if ("clear" in input && input.clear === true) return null;
  if ("keep" in input && input.keep === true) {
    if (isNew) return fail("err.draftKeepNew", { where });
    return stored(old, where);
  }
  return fail("err.draftSecretMalformed", { where });
}

type Existing = {
  raw: Obj;
  key: SymKey;
};

/// The old fields with their names opened (names are not secrets: the card
/// shows them), so a kept one is found by name.
async function oldFields(e: Existing | null): Promise<{ raw: Obj; name: string | null; type: number }[]> {
  if (!e) return [];
  const list = e.raw.fields ?? [];
  if (!Array.isArray(list)) return unreadable("cipher.fields");
  const out: { raw: Obj; name: string | null; type: number }[] = [];
  for (const [i, f] of list.entries()) {
    if (!isObj(f)) return unreadable(`cipher.fields[${i}]`);
    const type = f.type;
    if (typeof type !== "number" || !Number.isInteger(type)) return unreadable(`cipher.fields[${i}].type`);
    const sealedName = stored(f.name, `cipher.fields[${i}].name`);
    const name = sealedName === null ? null : (await decryptString(sealedName, e.key)).trim();
    out.push({ raw: f, name, type });
  }
  return out;
}

async function fieldsOf(key: SymKey, draft: ItemDraft, e: Existing | null): Promise<Obj[]> {
  const old = await oldFields(e);
  const used = new Set<number>();
  const take = (name: string, ok: (t: number) => boolean) => {
    const i = old.findIndex((f, n) => !used.has(n) && f.name === name && ok(f.type));
    if (i >= 0) used.add(i);
    return i >= 0 ? old[i]! : null;
  };
  const out: Obj[] = [];

  for (const f of draft.fields) {
    if (!("custom" in f)) continue;
    const name = typeof f.custom === "string" ? f.custom.trim() : "";
    if (name === "") fail("err.draftFieldNameEmpty");
    // `kw-*` fields belong to `tags` (and, hidden, to plugins): a custom
    // field by that name would be read as one.
    if (name.toLowerCase().startsWith(TAG_PREFIX)) fail("err.draftTagMalformed", { reason: "custom" });
    if (f.hidden === false) {
      if (typeof f.value !== "string") fail("err.draftSecretMalformed", { where: "field" });
      // A checkbox stays a checkbox while it says true or false.
      const was = take(name, (t) => t === FIELD_TEXT || t === FIELD_BOOLEAN);
      const type = was?.type === FIELD_BOOLEAN && (f.value === "true" || f.value === "false") ? FIELD_BOOLEAN : FIELD_TEXT;
      out.push({ type, name: await encryptText(key, name), value: await seal(key, f.value), linkedId: null });
    } else if (f.hidden === true) {
      const s = f.secret;
      if (isObj(s) && "keep" in s && s.keep === true) {
        if (!e) fail("err.draftKeepNew", { where: "field" });
        // The stored field, whole: its name, its value, its type.
        const was = take(name, (t) => t !== FIELD_BOOLEAN && t !== FIELD_LINKED) ?? fail("err.secretAbsent");
        stored(was.raw.value, "cipher.fields.value");
        out.push({ ...was.raw });
      } else {
        out.push({ type: FIELD_HIDDEN, name: await encryptText(key, name), value: await secretValue(key, s, null, "field", true), linkedId: null });
      }
    } else {
      fail("err.draftSecretMalformed", { where: "field" });
    }
  }

  // The item's own `kw-*` fields, as the window has them.
  if (!isObj(draft.tags)) fail("err.draftTagMalformed", { reason: "tags" });
  for (const [k, v] of Object.entries(draft.tags)) {
    const name = k.trim().toLowerCase();
    if (!name.startsWith(TAG_PREFIX) || name.length === TAG_PREFIX.length || typeof v !== "string") fail("err.draftTagMalformed", { reason: "tag" });
    out.push({ type: FIELD_TEXT, name: await encryptText(key, name), value: await seal(key, v), linkedId: null });
  }

  // What the draft cannot say goes back as it was: linked fields, hidden
  // `kw-*` fields (a plugin's secrets) and types newer than this client.
  // Visible `kw-*` fields are the draft's `tags`, so the old ones go.
  for (const [i, f] of old.entries()) {
    if (used.has(i)) continue;
    const tag = f.name !== null && f.name.toLowerCase().startsWith(TAG_PREFIX);
    const keep = f.type === FIELD_LINKED || f.type > FIELD_LINKED || (tag && f.type !== FIELD_TEXT);
    if (keep) out.push({ ...f.raw });
  }
  return out;
}

async function urisOf(key: SymKey, draft: ItemDraft, oldLogin: Obj | null, e: Existing | null): Promise<Obj[]> {
  if (!Array.isArray(draft.uris)) return fail("err.draftFieldUnknown", { key: "uris" });
  // The old ones by their text (a host is not a secret: the list shows it),
  // so an unchanged one keeps its match rule and checksum.
  const old: { text: string; raw: Obj }[] = [];
  const list = oldLogin?.uris ?? [];
  if (!Array.isArray(list)) return unreadable("cipher.login.uris");
  if (e) {
    for (const [i, u] of list.entries()) {
      if (!isObj(u)) return unreadable(`cipher.login.uris[${i}]`);
      const sealed = stored(u.uri, `cipher.login.uris[${i}].uri`);
      if (sealed !== null) old.push({ text: await decryptString(sealed, e.key), raw: u });
    }
  }
  const out: Obj[] = [];
  for (const u of draft.uris) {
    if (typeof u !== "string") fail("err.draftFieldUnknown", { key: "uris" });
    const text = u.trim();
    if (text === "") continue;
    const at = old.findIndex((o) => o.text === text);
    if (at >= 0) {
      out.push({ ...old[at]!.raw });
      old.splice(at, 1);
      continue;
    }
    // The checksum the official clients check an item-key item's URI by.
    const digest = await sha256(utf8(text));
    let sum: string;
    try {
      sum = toB64(digest);
    } finally {
      zero(digest);
    }
    out.push({ uri: await encryptText(key, text), uriChecksum: await encryptText(key, sum), match: null });
  }
  return out;
}

/// The cipher's body, every value sealed with `key`. `e` is the stored item
/// on an edit, `null` on a create.
async function cipherBody(key: SymKey, draft: ItemDraft, e: Existing | null, nowIso: string): Promise<Obj> {
  const kind = kindCode(draft.kind);
  const spec = PARTS[draft.kind];
  const name = typeof draft.name === "string" ? draft.name.trim() : "";
  if (name === "") fail("err.draftNameEmpty");
  if (!Array.isArray(draft.fields)) fail("err.draftFieldUnknown", { key: "fields" });

  const oldPart = e && isObj(e.raw[spec.part]) ? (e.raw[spec.part] as Obj) : null;
  const part: Obj = oldPart ? { ...oldPart } : {};
  if (!e) for (const wire of Object.values(spec.keys)) part[wire] = null;

  const seen = new Set<string>();
  let passwordChanged = false;
  for (const f of draft.fields as DraftField[]) {
    if (!("key" in f)) continue;
    const k = f.key;
    const wire = typeof k === "string" && Object.prototype.hasOwnProperty.call(spec.keys, k) ? spec.keys[k]! : fail("err.draftFieldUnknown", { key: String(k) });
    if (seen.has(k)) fail("err.draftFieldTwice", { key: k });
    seen.add(k);
    if ("secret" in f) {
      const isKeep = isObj(f.secret) && "keep" in f.secret && f.secret.keep === true;
      part[wire] = await secretValue(key, f.secret, oldPart?.[wire], k, e === null);
      if (draft.kind === ItemKind.Login && wire === "password" && !isKeep) passwordChanged = true;
    } else if ("value" in f && typeof f.value === "string") {
      part[wire] = await seal(key, f.value);
      if (draft.kind === ItemKind.Login && wire === "password") passwordChanged = true;
    } else {
      fail("err.draftSecretMalformed", { where: k });
    }
  }

  let history: unknown[] = [];
  if (e) {
    const h = e.raw.passwordHistory ?? [];
    if (!Array.isArray(h)) return unreadable("cipher.passwordHistory");
    history = h.map((x) => (isObj(x) ? { ...x } : unreadable("cipher.passwordHistory")));
  }

  if (draft.kind === ItemKind.Login) {
    part.uris = await urisOf(key, draft, oldPart, e);
    // Passkeys go back untouched: the login part is replaced whole, and a
    // passkey lost is lost for good.
    if (!Array.isArray(part.fido2Credentials)) part.fido2Credentials = part.fido2Credentials == null ? [] : unreadable("cipher.login.fido2Credentials");
    if (passwordChanged) {
      // The old password into the history as the EncString it was: an edit
      // never opens it to decide whether it changed.
      const was = e ? stored(oldPart?.password, "cipher.login.password") : null;
      if (was !== null) history = [{ password: was, lastUsedDate: nowIso }, ...history].slice(0, HISTORY_MAX);
      part.passwordRevisionDate = part.password === null && was === null ? (part.passwordRevisionDate ?? null) : nowIso;
    }
  } else if (Array.isArray(draft.uris) && draft.uris.some((u) => typeof u !== "string" || u.trim() !== "")) {
    fail("err.draftFieldUnknown", { key: "uris" });
  }
  if (draft.kind === ItemKind.SecureNote && !isObj(oldPart)) part.type = 0;

  const notesOld = e ? e.raw.notes : null;
  const body: Obj = {
    type: kind,
    organizationId: draft.orgId,
    folderId: draft.folderId,
    name: await encryptText(key, name),
    notes: await secretValue(key, draft.notes, notesOld, "notes", e === null),
    favorite: draft.favorite === true,
    reprompt: draft.reprompt === true ? 1 : 0,
    // An item's own key goes back as it is: the server stores what arrives,
    // and an item without its key can never be opened again.
    key: e ? stored(e.raw.key, "cipher.key") : null,
    [spec.part]: part,
    fields: await fieldsOf(key, draft, e),
    passwordHistory: history,
  };
  if (e) {
    const rev = e.raw.revisionDate;
    // The server refuses an edit of an item that changed since: a write
    // never lands over one made elsewhere.
    if (typeof rev === "string" && rev !== "") body.lastKnownRevisionDate = rev;
  }
  return body;
}

// --- merging ----------------------------------------------------------------
//
// The copies of one login made one, here where the keys are: a value is
// opened with its record's key only to be compared or sealed again with the
// kept record's, and never leaves this file but as a group number or an
// EncString.

type Rec = { id: string; raw: Obj; key: SymKey };
/// What a record holds in a slot: the opened value (a linked field's link
/// stands for its value), its field type, and its link.
type Held = { slot: MergeSlot; secret: boolean; value: string; type: number; linkedId: unknown };
/// The one field of a stored passkey left in the clear.
const PASSKEY_PLAIN = new Set(["creationDate"]);
const BUILTIN_WIRE = { [MergeField.Username]: "username", [MergeField.Password]: "password", [MergeField.Totp]: "totp" } as const;

async function opened(v: unknown, key: SymKey, where: string): Promise<string | null> {
  const sealed = stored(v, where);
  if (sealed === null) return null;
  const text = await decryptString(sealed, key);
  return text === "" ? null : text;
}
function loginOf(r: Rec): Obj {
  return r.raw.type === KIND_CODE[ItemKind.Login] && isObj(r.raw.login) ? r.raw.login : fail("err.mergeOnlyLogins");
}
function passkeysOf(r: Rec): Obj[] {
  const list = loginOf(r).fido2Credentials ?? [];
  if (!Array.isArray(list)) return unreadable("cipher.login.fido2Credentials");
  return list.map((c, i) => (isObj(c) ? c : unreadable(`cipher.login.fido2Credentials[${i}]`)));
}

/// Every slot a record holds, by its key, in the order a comparison lists
/// them.
async function heldOf(r: Rec): Promise<Map<string, Held>> {
  const login = loginOf(r);
  const out = new Map<string, Held>();
  for (const field of [MergeField.Username, MergeField.Password, MergeField.Totp] as const) {
    const v = await opened(login[BUILTIN_WIRE[field]], r.key, `cipher.login.${BUILTIN_WIRE[field]}`);
    const secret = field !== MergeField.Username;
    if (v !== null) out.set(field, { slot: { field }, secret, value: v, type: secret ? FIELD_HIDDEN : FIELD_TEXT, linkedId: null });
  }
  const notes = await opened(r.raw.notes, r.key, "cipher.notes");
  if (notes !== null) out.set(MergeField.Notes, { slot: { field: MergeField.Notes }, secret: true, value: notes, type: FIELD_HIDDEN, linkedId: null });
  for (const f of await oldFields(r)) {
    const name = f.name ?? fail("err.mergeUnnamedField");
    const slot: MergeSlot = { field: MergeField.Custom, name };
    if (out.has(slotKey(slot))) fail("err.mergeFieldNamedTwice", { name });
    const value = f.type === FIELD_LINKED ? `\0linked:${String(f.raw.linkedId)}` : ((await opened(f.raw.value, r.key, "cipher.fields.value")) ?? "");
    out.set(slotKey(slot), { slot, secret: f.type === FIELD_HIDDEN, value, type: f.type, linkedId: f.raw.linkedId ?? null });
  }
  if (passkeysOf(r).length) out.set(MergeField.Passkeys, { slot: { field: MergeField.Passkeys }, secret: false, value: `\0passkeys:${r.id}`, type: FIELD_TEXT, linkedId: null });
  return out;
}

/// The comparison of records, in the order asked: who holds what and who
/// agrees, never a value.
function comparisonOf(recs: { id: string; held: Map<string, Held> }[]): MergeComparison {
  const rows = new Map<string, MergeRow & { values: string[] }>();
  const order = (k: string) => (k === MergeField.Passkeys ? 2 : k.startsWith("custom:") ? 1 : 0);
  for (const r of recs)
    for (const [k, h] of r.held) {
      let row = rows.get(k);
      if (!row) rows.set(k, (row = { slot: h.slot, secret: h.secret, holders: [], values: [] }));
      row.secret ||= h.secret;
      let group = row.values.indexOf(h.value);
      if (group < 0) group = row.values.push(h.value) - 1;
      row.holders.push({ itemId: r.id, group });
    }
  const list = [...rows.entries()].sort((a, b) => order(a[0]) - order(b[0]));
  return { rows: list.map(([, { values: _, ...row }]) => row) };
}

/// A passkey of one record sealed again for another.
async function resealed(c: Obj, from: SymKey, into: SymKey): Promise<Obj> {
  const out: Obj = {};
  for (const [k, v] of Object.entries(c)) out[k] = typeof v === "string" && v !== "" && !PASSKEY_PLAIN.has(k) ? await encryptText(into, await decryptString(stored(v, `fido2Credentials.${k}`)!, from)) : v;
  return out;
}

/// An address and the checksum the official clients check it by.
async function sealedUri(key: SymKey, text: string): Promise<Obj> {
  const digest = await sha256(utf8(text));
  let sum: string;
  try {
    sum = toB64(digest);
  } finally {
    zero(digest);
  }
  return { uri: await encryptText(key, text), uriChecksum: await encryptText(key, sum), match: null };
}

/// The kept record's new body: its own values as the EncStrings they are,
/// the plan's fields opened from their records and sealed for it, and every
/// record's addresses.
async function mergedBody(keeper: Rec, others: Map<string, Rec>, plan: MergePlan, nowIso: string): Promise<Obj> {
  const raw = keeper.raw;
  const login: Obj = { ...loginOf(keeper) };
  const uris = Array.isArray(login.uris) ? login.uris.map((u, i) => (isObj(u) ? { ...u } : unreadable(`cipher.login.uris[${i}]`))) : login.uris == null ? [] : unreadable("cipher.login.uris");
  const texts: string[] = [];
  for (const u of uris) {
    const t = await opened(u.uri, keeper.key, "cipher.login.uris.uri");
    if (t !== null) texts.push(t.trim().toLowerCase());
  }
  for (const r of others.values()) {
    const list = loginOf(r).uris ?? [];
    if (!Array.isArray(list)) return unreadable("cipher.login.uris");
    for (const u of list) {
      const t = isObj(u) ? await opened(u.uri, r.key, "cipher.login.uris.uri") : unreadable("cipher.login.uris");
      if (t === null || texts.includes(t.trim().toLowerCase())) continue;
      texts.push(t.trim().toLowerCase());
      uris.push(await sealedUri(keeper.key, t.trim()));
    }
  }
  login.uris = uris;
  const passkeys = passkeysOf(keeper).map((c) => ({ ...c }));
  const fields = (await oldFields(keeper)).map((f) => ({ ...f, raw: { ...f.raw } }));
  let notes = stored(raw.notes, "cipher.notes");
  const h = raw.passwordHistory ?? [];
  if (!Array.isArray(h)) return unreadable("cipher.passwordHistory");
  let history = h.map((x) => (isObj(x) ? { ...x } : unreadable("cipher.passwordHistory")));

  const held = new Map<string, Map<string, Held>>();
  for (const take of plan.takes) {
    const from = others.get(take.from) ?? fail("err.mergeForeignTake");
    if (take.slot.field === MergeField.Passkeys) {
      const list = passkeysOf(from);
      if (!list.length) fail("err.mergeFieldGone");
      for (const c of list) passkeys.push(await resealed(c, from.key, keeper.key));
      continue;
    }
    let theirs = held.get(from.id);
    if (!theirs) held.set(from.id, (theirs = await heldOf(from)));
    const got = theirs.get(slotKey(take.slot)) ?? fail("err.mergeFieldGone");
    const linked = got.type === FIELD_LINKED;
    const value = linked ? null : await encryptText(keeper.key, got.value);
    if (take.asName !== null) {
      const name = take.asName.trim();
      if (fields.some((f) => f.name !== null && f.name.toLowerCase() === name.toLowerCase())) fail("err.mergeNameTaken", { name });
      fields.push({ raw: { type: got.type, name: await encryptText(keeper.key, name), value, linkedId: linked ? got.linkedId : null }, name, type: got.type });
      continue;
    }
    switch (take.slot.field) {
      case MergeField.Username:
      case MergeField.Totp:
        login[BUILTIN_WIRE[take.slot.field]] = value;
        break;
      case MergeField.Password: {
        // The replaced password into the history as the EncString it was.
        const was = stored(login.password, "cipher.login.password");
        if (was !== null) history = [{ password: was, lastUsedDate: nowIso }, ...history].slice(0, HISTORY_MAX);
        login.password = value;
        login.passwordRevisionDate = nowIso;
        break;
      }
      case MergeField.Notes:
        notes = value;
        break;
      case MergeField.Custom: {
        const name = take.slot.name;
        const at = fields.findIndex((f) => f.name !== null && f.name.toLowerCase() === name.toLowerCase());
        const field = { type: got.type, name: at >= 0 ? fields[at]!.raw.name : await encryptText(keeper.key, name), value, linkedId: linked ? got.linkedId : null };
        if (at >= 0) fields[at] = { raw: field, name: fields[at]!.name, type: got.type };
        else fields.push({ raw: field, name, type: got.type });
        break;
      }
    }
  }
  login.fido2Credentials = passkeys;
  const body: Obj = {
    type: raw.type,
    organizationId: raw.organizationId ?? null,
    folderId: raw.folderId ?? null,
    name: stored(raw.name, "cipher.name"),
    notes,
    favorite: raw.favorite === true,
    reprompt: raw.reprompt === 1 ? 1 : 0,
    key: stored(raw.key, "cipher.key"),
    login,
    fields: fields.map((f) => f.raw),
    passwordHistory: history,
  };
  if (typeof raw.revisionDate === "string" && raw.revisionDate !== "") body.lastKnownRevisionDate = raw.revisionDate;
  return body;
}

// --- the writes ---------------------------------------------------------------

/// A digest of the login's password hash: it can check a password, it cannot
/// log anyone in.
const VERIFIER_DOMAIN = utf8("keyward.web.verify.v1");

export class WebWrites implements Writes {
  private verifier: Bytes | null = null;

  constructor(private readonly host: WriteHost) {}

  /// Called by the session with the hash a login or an unlock derived.
  async remember(passwordHash: string): Promise<void> {
    this.forget();
    const h = utf8(passwordHash);
    try {
      this.verifier = await sha256(VERIFIER_DOMAIN, h);
    } finally {
      zero(h);
    }
  }

  /// On lock and log-out.
  forget(): void {
    zero(this.verifier);
    this.verifier = null;
  }

  async verifyPassword(password: string): Promise<boolean> {
    this.host.open();
    const want = this.verifier ?? fail("err.locked");
    const { email, kdf } = this.host.account();
    const mk = await deriveMasterKey(password, email, kdf);
    let hash: string;
    try {
      hash = await masterPasswordHash(mk, password);
    } finally {
      zero(mk);
    }
    const h = utf8(hash);
    let got: Bytes | null = null;
    try {
      got = await sha256(VERIFIER_DOMAIN, h);
      // A lock while the KDF ran took the verifier with it.
      if (this.verifier !== want) fail("err.locked");
      return constantTimeEqual(got, want);
    } finally {
      zero(h, got);
    }
  }

  async create(draft: ItemDraft): Promise<string> {
    const { ring, snapshot } = this.host.open();
    this.placeOf(draft, snapshot, ring);
    const key = ring.base(draft.orgId);
    const body = await cipherBody(key, draft, null, this.nowIso());
    this.same(ring);
    const answerBody =
      draft.orgId === null
        ? await this.host.authed("POST", "ciphers", body)
        : await this.host.authed("POST", "ciphers/create", { cipher: body, collectionIds: [...new Set(draft.collectionIds)] });
    const id = idOf(answer(answerBody, "cipher"), "cipher");
    await this.after({ kind: ChangeKind.Item, id });
    return id;
  }

  async update(id: string, draft: ItemDraft): Promise<void> {
    const { ring, snapshot } = this.host.open();
    pathId(id);
    if (!(await this.host.catalog()).items.some((i) => i.id === id)) fail("err.itemNotFound");
    const raw = answer(await this.host.authed("GET", `ciphers/${id}`), "cipher");
    if (idOf(raw, "cipher") !== id) unreadable("cipher.id");
    if (raw.deletedDate !== undefined && raw.deletedDate !== null && raw.deletedDate !== "") fail("err.itemInTrash");
    if (raw.type !== kindCode(draft.kind)) fail("err.itemKindChange");
    const org = raw.organizationId === undefined || raw.organizationId === null || raw.organizationId === "" ? null : raw.organizationId;
    if (org !== null && typeof org !== "string") unreadable("cipher.organizationId");
    // Moving an item between owners re-seals every value, the kept ones too;
    // this edit does not open stored secrets, so it does not move items.
    if (org !== draft.orgId) fail("err.itemOrgChange");
    this.placeOf(draft, snapshot, ring);

    const base = ring.base(org as string | null);
    const own = stored(raw.key, "cipher.key");
    const key = own === null ? base : await unwrapSymKey(own, base);
    const body = await cipherBody(key, draft, { raw, key }, this.nowIso());
    this.same(ring);
    await this.host.authed("PUT", `ciphers/${id}`, body);

    if (org !== null) {
      const before = Array.isArray(raw.collectionIds) ? raw.collectionIds.filter((c): c is string => typeof c === "string") : [];
      const after = [...new Set(draft.collectionIds)];
      const changed = before.length !== after.length || after.some((c) => !before.includes(c));
      if (changed) await this.host.authed("PUT", `ciphers/${id}/collections`, { collectionIds: after });
    }
    await this.after({ kind: ChangeKind.Item, id });
  }

  /// A record of the vault, fresh from the server, with the key its values
  /// are sealed with; one in the trash is not merged.
  private async record(id: string, ring: KeyRing, listed: Set<string>): Promise<Rec> {
    pathId(id);
    if (!listed.has(id)) fail("err.itemNotFound");
    const raw = answer(await this.host.authed("GET", `ciphers/${id}`), "cipher");
    if (idOf(raw, "cipher") !== id) unreadable("cipher.id");
    if (raw.deletedDate !== undefined && raw.deletedDate !== null && raw.deletedDate !== "") fail("err.mergeInTrash");
    const org = raw.organizationId === undefined || raw.organizationId === null || raw.organizationId === "" ? null : raw.organizationId;
    if (org !== null && typeof org !== "string") unreadable("cipher.organizationId");
    const base = ring.base(org as string | null);
    const own = stored(raw.key, "cipher.key");
    return { id, raw, key: own === null ? base : await unwrapSymKey(own, base) };
  }
  private async listed(): Promise<Set<string>> {
    return new Set((await this.host.catalog()).items.filter((i) => !i.deleted).map((i) => i.id));
  }

  async compareForMerge(itemIds: string[]): Promise<MergeComparison> {
    if (itemIds.length < 2) fail("err.mergeNothing");
    const { ring } = this.host.open();
    const listed = await this.listed();
    const recs = await Promise.all(itemIds.map((id) => this.record(id, ring, listed)));
    return comparisonOf(await Promise.all(recs.map(async (r) => ({ id: r.id, held: await heldOf(r) }))));
  }

  async merge(plan: MergePlan): Promise<void> {
    const refused = planRefusal(plan);
    if (refused) fail(refused);
    const { ring } = this.host.open();
    const listed = await this.listed();
    const keeper = await this.record(plan.keeper, ring, listed);
    const others = new Map<string, Rec>();
    for (const id of plan.others) others.set(id, await this.record(id, ring, listed));
    const body = await mergedBody(keeper, others, plan, this.nowIso());
    this.same(ring);
    await this.host.authed("PUT", `ciphers/${keeper.id}`, body);
    // Only once the kept record is saved do the copies go, and to the trash.
    for (const id of plan.others) await this.host.authed("PUT", `ciphers/${id}/delete`);
    await this.after({ kind: ChangeKind.Catalog });
  }

  async generate(opts: GeneratorOptions): Promise<{ value: string; drop: () => void }> {
    if (!isObj(opts)) return fail("err.generatorNoCharset");
    if (opts.kind === GeneratorKind.Password) return shown(password(opts));
    if (opts.kind === GeneratorKind.Passphrase) return shown(passphrase(opts));
    return fail("err.generatorKindUnknown", { kind: String((opts as { kind: unknown }).kind) });
  }

  // --- folders ---

  async createFolder(name: string): Promise<string> {
    const { ring } = this.host.open();
    const sealed = await encryptText(ring.userKey(), this.nameOf(name));
    this.same(ring);
    const id = idOf(answer(await this.host.authed("POST", "folders", { name: sealed }), "folder"), "folder");
    await this.after();
    return id;
  }

  async renameFolder(id: string, name: string): Promise<void> {
    const { ring } = this.host.open();
    this.folder(id);
    const sealed = await encryptText(ring.userKey(), this.nameOf(name));
    this.same(ring);
    await this.host.authed("PUT", `folders/${id}`, { name: sealed });
    await this.after();
  }

  /// The server leaves the folder's items without a folder.
  async deleteFolder(id: string): Promise<void> {
    this.folder(id);
    await this.host.authed("DELETE", `folders/${id}`);
    await this.after();
  }

  // --- collections ---

  async createCollection(orgId: string, name: string): Promise<string> {
    const { ring } = this.host.open();
    this.org(orgId, "manageCollections");
    const sealed = await encryptText(ring.base(orgId), this.nameOf(name));
    this.same(ring);
    const answerBody = await this.host.authed("POST", `organizations/${orgId}/collections`, { name: sealed, groups: [], users: [] });
    const id = idOf(answer(answerBody, "collection"), "collection");
    await this.after();
    return id;
  }

  /// A rename sends the collection's grants back as they are: the server
  /// replaces them with what arrives, and an empty list would take every
  /// member's access away.
  async renameCollection(orgId: string, id: string, name: string): Promise<void> {
    const { ring } = this.host.open();
    this.org(orgId, "manageCollections");
    this.collection(orgId, id);
    const sealed = await encryptText(ring.base(orgId), this.nameOf(name));
    const details = answer(await this.host.authed("GET", `organizations/${orgId}/collections/${id}/details`), "collection");
    if (idOf(details, "collection") !== id) unreadable("collection.id");
    const grants = (k: "users" | "groups") => {
      const list = details[k] ?? [];
      if (!Array.isArray(list)) return unreadable(`collection.${k}`);
      return list.map((g, i) => {
        if (!isObj(g) || typeof g.id !== "string") return unreadable(`collection.${k}[${i}]`);
        return { id: g.id, readOnly: g.readOnly === true, hidePasswords: g.hidePasswords === true, manage: g.manage === true };
      });
    };
    const body = { name: sealed, externalId: typeof details.externalId === "string" ? details.externalId : null, users: grants("users"), groups: grants("groups") };
    this.same(ring);
    await this.host.authed("PUT", `organizations/${orgId}/collections/${id}`, body);
    await this.after();
  }

  async deleteCollection(orgId: string, id: string): Promise<void> {
    this.org(orgId, "manageCollections");
    this.collection(orgId, id);
    await this.host.authed("DELETE", `organizations/${orgId}/collections/${id}`);
    await this.after();
  }

  // --- members ---

  /// The organisation key is not handed over here: the invited person
  /// accepts first, and is then confirmed with it (`confirmMember`).
  async invite(orgId: string, invite: Invite): Promise<void> {
    this.org(orgId, "manageMembers");
    if (!isObj(invite) || !Array.isArray(invite.emails)) return fail("err.inviteEmpty");
    const emails = [...new Set(invite.emails.map((e) => (typeof e === "string" ? e.trim().toLowerCase() : "")))].filter((e) => e !== "");
    if (emails.length === 0) fail("err.inviteEmpty");
    // The server's own limit for one invitation.
    if (emails.length > 20) fail("err.inviteTooMany", { max: 20 });
    for (const e of emails) if (!/^[^\s@]+@[^\s@]+$/.test(e) || e.length > 256) fail("err.inviteEmailMalformed");
    await this.host.authed("POST", `organizations/${orgId}/users/invite`, {
      emails,
      type: roleCode(invite.role),
      accessAll: invite.accessAll === true,
      collections: this.grants(orgId, invite.accessAll === true, invite.access),
      permissions: {},
    });
    await this.after();
  }

  async setMember(orgId: string, memberId: string, change: { role: OrgRole; accessAll: boolean; access: Record<string, Permission> }): Promise<void> {
    this.org(orgId, "manageMembers");
    pathId(memberId);
    if (!isObj(change)) fail("err.memberNotFound");
    // `groups` is left out: the server then leaves the member's groups as
    // they are, where an empty list would take them away.
    await this.host.authed("PUT", `organizations/${orgId}/users/${memberId}`, {
      type: roleCode(change.role),
      accessAll: change.accessAll === true,
      collections: this.grants(orgId, change.accessAll === true, change.access),
      permissions: {},
    });
    await this.after();
  }

  /// The member's public key as the server gives it now, and the five words
  /// it makes for them: only someone who accepted the invitation has one.
  private async memberKey(orgId: string, memberId: string): Promise<{ userId: string; spki: string; words: string[] }> {
    this.org(orgId, "manageMembers");
    pathId(memberId);
    const member = answer(await this.host.authed("GET", `organizations/${orgId}/users/${memberId}`), "member");
    if (idOf(member, "member") !== memberId) unreadable("member.id");
    if (member.status !== 1) fail("err.memberNotAccepted");
    const userId = member.userId;
    if (typeof userId !== "string" || !isPathId(userId)) return unreadable("member.userId");
    const pk = answer(await this.host.authed("GET", `users/${userId}/public-key`), "publicKey");
    if (typeof pk.publicKey !== "string" || pk.publicKey === "") return unreadable("publicKey");
    let der: Bytes;
    try {
      der = fromB64(pk.publicKey);
    } catch {
      return fail("err.memberKeyMalformed", { reason: "base64" });
    }
    return { userId, spki: pk.publicKey, words: await fingerprintPhrase(userId, der) };
  }

  /// The member's fingerprint phrase, to compare with them out of band.
  async memberFingerprint(orgId: string, memberId: string): Promise<string[]> {
    return (await this.memberKey(orgId, memberId)).words;
  }

  /// Hands the member the organisation key, sealed with their own public
  /// key: only someone who accepted the invitation, only from an
  /// organisation whose key this session holds, and only to a key that still
  /// makes the words the person was shown.
  async confirmMember(orgId: string, memberId: string, fingerprint: string[]): Promise<void> {
    const { ring, snapshot } = this.host.open();
    const org = this.org(orgId, "manageMembers");
    pathId(memberId);
    if (!ring.hasOrg(orgId) || org.key === null) fail("err.noOrgKey");
    const key = await this.memberKey(orgId, memberId);
    if (!Array.isArray(fingerprint) || fingerprint.length !== key.words.length || fingerprint.some((w, i) => w !== key.words[i])) fail("err.fingerprintChanged");
    const publicKey = await importMemberPublicKey(key.spki);

    // The sealed form this sync brought, opened once more; the ring's own
    // key cannot be read back out.
    const sealedOrg = snapshot.profile.organizations.find((o) => o.id === orgId)?.key ?? fail("err.noOrgKey");
    const raw = await ring.orgKeyBytes(orgId, sealedOrg);
    let sealed: string;
    try {
      sealed = await sealForMember(publicKey, raw);
    } finally {
      zero(raw);
    }
    this.same(ring);
    await this.host.authed("POST", `organizations/${orgId}/users/${memberId}/confirm`, { key: sealed });
    await this.after();
  }

  async removeMember(orgId: string, memberId: string): Promise<void> {
    this.org(orgId, "manageMembers");
    pathId(memberId);
    const me = (await this.host.catalog()).members.find((m) => m.orgId === orgId && m.id === memberId);
    // Leaving is its own action; removing oneself would lock one out of the
    // organisation's items with no way back but another admin.
    if (me?.isYou) fail("err.cannotRemoveSelf");
    await this.host.authed("POST", `organizations/${orgId}/users/${memberId}/delete`);
    await this.after();
  }

  // --- small things ---

  private nowIso(): string {
    return new Date(this.host.now()).toISOString();
  }

  /// A lock that came while the values were being sealed wins: nothing is
  /// sent from a session that is no longer open.
  private same(ring: KeyRing): void {
    if (this.host.open().ring !== ring) fail("err.locked");
  }

  private async after(change?: Change): Promise<void> {
    await this.host.sync();
    if (change) this.host.emit(change);
  }

  private nameOf(name: string): string {
    const n = typeof name === "string" ? name.trim() : "";
    return n === "" ? fail("err.nameEmpty") : n;
  }

  private folder(id: string): void {
    pathId(id);
    const { snapshot } = this.host.open();
    if (!snapshot.folders.some((f) => f.id === id)) fail("err.folderNotFound");
  }

  private org(orgId: string, need: "manageCollections" | "manageMembers"): SyncOrg {
    pathId(orgId);
    const { snapshot } = this.host.open();
    const org = snapshot.profile.organizations.find((o) => o.id === orgId) ?? fail("err.orgNotFound");
    if (!abilitiesOf(org)[need]) fail("err.notAllowed");
    return org;
  }

  private collection(orgId: string, id: string): void {
    pathId(id);
    const { snapshot } = this.host.open();
    if (!snapshot.collections.some((c) => c.id === id && c.organizationId === orgId)) fail("err.collectionNotFound");
  }

  /// Collection grants for an invitation or a change. With `accessAll` there
  /// are none to give.
  private grants(orgId: string, accessAll: boolean, access: Record<string, Permission>): Obj[] {
    if (!isObj(access)) return fail("err.collectionNotFound");
    const entries = Object.entries(access);
    if (accessAll) {
      if (entries.length) fail("err.accessAllWithGrants");
      return [];
    }
    return entries.map(([id, p]) => {
      this.collection(orgId, id);
      return { id, ...grantOf(p) };
    });
  }

  /// Where a draft puts an item: a folder of this account, an organisation
  /// whose key the session holds, and its collections — writable, and only
  /// with an organisation.
  private placeOf(draft: ItemDraft, snapshot: SyncData, ring: KeyRing): void {
    if (!isObj(draft)) fail("err.itemKindUnknown", { kind: "draft" });
    kindCode(draft.kind);
    if (draft.folderId !== null) {
      if (typeof draft.folderId !== "string" || !snapshot.folders.some((f) => f.id === draft.folderId)) fail("err.folderNotFound");
    }
    if (!Array.isArray(draft.collectionIds)) fail("err.collectionNotFound");
    if (draft.orgId === null) {
      if (draft.collectionIds.length) fail("err.collectionWithoutOrg");
      return;
    }
    if (typeof draft.orgId !== "string" || !ring.hasOrg(draft.orgId)) fail("err.noOrgKey");
    if (draft.collectionIds.length === 0) fail("err.collectionRequired");
    for (const id of draft.collectionIds) {
      const c = snapshot.collections.find((x) => x.id === id && x.organizationId === draft.orgId) ?? fail("err.collectionNotFound");
      if (c.readOnly) fail("err.collectionReadOnly");
    }
  }
}
