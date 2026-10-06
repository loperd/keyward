// The `/api/sync` answer, read into a model whose values stay ENCRYPTED: this
// layer only checks shapes. Field names come in either casing (Vaultwarden
// writes camelCase, older servers PascalCase), and a `null` where a list or a
// flag belongs is everyday and reads as empty. A value of the wrong type is
// not everyday: it is refused, with where it was, so a broken answer never
// turns quietly into a smaller vault.
import { fail } from "./errors";

type Json = unknown;
type Obj = Record<string, Json>;

export type SyncProfile = {
  id: string;
  email: string;
  name: string | null;
  key: string | null;
  privateKey: string | null;
  organizations: SyncOrg[];
};

export type SyncOrgPermissions = {
  manageUsers: boolean;
  createNewCollections: boolean;
  editAnyCollection: boolean;
  deleteAnyCollection: boolean;
};

export type SyncOrg = {
  id: string;
  /// In the clear: an organisation's name is common to all its members.
  name: string;
  key: string | null;
  /// 0 owner, 1 admin, 2 user, 3 manager, 4 custom.
  type: number;
  status: number;
  permissions: SyncOrgPermissions;
};

export type SyncFolder = { id: string; name: string };
export type SyncCollection = { id: string; name: string; organizationId: string; readOnly: boolean };

export type SyncField = { type: number; name: string | null; value: string | null; linkedId: number | null };
export type SyncLogin = {
  username: string | null;
  password: string | null;
  totp: string | null;
  uris: string[];
  passkeys: Obj[];
  passwordRevisionDate: string | null;
};
export type SyncCard = {
  cardholderName: string | null;
  number: string | null;
  brand: string | null;
  expMonth: string | null;
  expYear: string | null;
  code: string | null;
};
export type SyncIdentity = {
  firstName: string | null;
  lastName: string | null;
  email: string | null;
  phone: string | null;
  username: string | null;
};
export type SyncSshKey = { privateKey: string | null; publicKey: string | null; fingerprint: string | null };
export type SyncHistory = { password: string | null; lastUsedDate: string | null };

export type SyncCipher = {
  id: string;
  type: number;
  name: string;
  notes: string | null;
  folderId: string | null;
  organizationId: string | null;
  collectionIds: string[];
  key: string | null;
  favorite: boolean;
  reprompt: number;
  deletedDate: string | null;
  revisionDate: string | null;
  passwordHistory: SyncHistory[];
  fields: SyncField[];
  login: SyncLogin | null;
  card: SyncCard | null;
  identity: SyncIdentity | null;
  sshKey: SyncSshKey | null;
};

export type SyncData = {
  profile: SyncProfile;
  folders: SyncFolder[];
  collections: SyncCollection[];
  ciphers: SyncCipher[];
};

/// An empty or blank date is no date: a server that sent `"deletedDate": ""`
/// would otherwise sweep the whole vault into the trash.
export const inTrash = (c: SyncCipher) => c.deletedDate !== null && c.deletedDate.trim() !== "";

const bad = (where: string): never => fail("err.syncUnreadable", { reason: where });

const isObj = (v: Json): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/// A field by either spelling; `undefined` and `null` both read as absent.
function raw(o: Obj, camel: string): Json {
  const pascal = camel[0]!.toUpperCase() + camel.slice(1);
  const v = camel in o ? o[camel] : o[pascal];
  return v === undefined ? null : v;
}

function optStr(o: Obj, name: string, where: string): string | null {
  const v = raw(o, name);
  if (v === null) return null;
  if (typeof v !== "string") return bad(`${where}.${name}`);
  return v;
}

function reqStr(o: Obj, name: string, where: string): string {
  const v = optStr(o, name, where);
  if (v === null || v === "") return bad(`${where}.${name}`);
  return v;
}

function num(o: Obj, name: string, where: string, absent: number): number {
  const v = raw(o, name);
  if (v === null) return absent;
  if (typeof v !== "number" || !Number.isInteger(v)) return bad(`${where}.${name}`);
  return v;
}

function bool(o: Obj, name: string, where: string): boolean {
  const v = raw(o, name);
  if (v === null) return false;
  if (typeof v !== "boolean") return bad(`${where}.${name}`);
  return v;
}

function list(o: Obj, name: string, where: string): Json[] {
  const v = raw(o, name);
  if (v === null) return [];
  if (!Array.isArray(v)) return bad(`${where}.${name}`);
  return v;
}

function objOrNull(o: Obj, name: string, where: string): Obj | null {
  const v = raw(o, name);
  if (v === null) return null;
  if (!isObj(v)) return bad(`${where}.${name}`);
  return v;
}

const each = <T>(items: Json[], where: string, read: (o: Obj, where: string) => T): T[] =>
  items.map((v, i) => (isObj(v) ? read(v, `${where}[${i}]`) : bad(`${where}[${i}]`)));

function readOrg(o: Obj, w: string): SyncOrg {
  const p = objOrNull(o, "permissions", w) ?? {};
  return {
    id: reqStr(o, "id", w),
    name: optStr(o, "name", w) ?? "",
    key: optStr(o, "key", w),
    type: num(o, "type", w, -1),
    status: num(o, "status", w, -1),
    permissions: {
      manageUsers: bool(p, "manageUsers", `${w}.permissions`),
      createNewCollections: bool(p, "createNewCollections", `${w}.permissions`),
      editAnyCollection: bool(p, "editAnyCollection", `${w}.permissions`),
      deleteAnyCollection: bool(p, "deleteAnyCollection", `${w}.permissions`),
    },
  };
}

function readCipher(o: Obj, w: string): SyncCipher {
  const login = objOrNull(o, "login", w);
  const card = objOrNull(o, "card", w);
  const identity = objOrNull(o, "identity", w);
  const ssh = objOrNull(o, "sshKey", w);
  const lw = `${w}.login`;
  return {
    id: reqStr(o, "id", w),
    type: num(o, "type", w, 0),
    name: reqStr(o, "name", w),
    notes: optStr(o, "notes", w),
    folderId: optStr(o, "folderId", w),
    organizationId: optStr(o, "organizationId", w),
    collectionIds: list(o, "collectionIds", w).map((v, i) => (typeof v === "string" ? v : bad(`${w}.collectionIds[${i}]`))),
    key: optStr(o, "key", w),
    favorite: bool(o, "favorite", w),
    reprompt: num(o, "reprompt", w, 0),
    deletedDate: optStr(o, "deletedDate", w),
    revisionDate: optStr(o, "revisionDate", w),
    passwordHistory: each(list(o, "passwordHistory", w), `${w}.passwordHistory`, (h, hw) => ({
      password: optStr(h, "password", hw),
      lastUsedDate: optStr(h, "lastUsedDate", hw),
    })),
    fields: each(list(o, "fields", w), `${w}.fields`, (f, fw) => ({
      type: num(f, "type", fw, 0),
      name: optStr(f, "name", fw),
      value: optStr(f, "value", fw),
      linkedId: raw(f, "linkedId") === null ? null : num(f, "linkedId", fw, 0),
    })),
    login: login && {
      username: optStr(login, "username", lw),
      password: optStr(login, "password", lw),
      totp: optStr(login, "totp", lw),
      uris: each(list(login, "uris", lw), `${lw}.uris`, (u, uw) => optStr(u, "uri", uw)).filter((u): u is string => u !== null),
      passkeys: each(list(login, "fido2Credentials", lw), `${lw}.fido2Credentials`, (p) => p),
      passwordRevisionDate: optStr(login, "passwordRevisionDate", lw),
    },
    card: card && {
      cardholderName: optStr(card, "cardholderName", `${w}.card`),
      number: optStr(card, "number", `${w}.card`),
      brand: optStr(card, "brand", `${w}.card`),
      expMonth: optStr(card, "expMonth", `${w}.card`),
      expYear: optStr(card, "expYear", `${w}.card`),
      code: optStr(card, "code", `${w}.card`),
    },
    identity: identity && {
      firstName: optStr(identity, "firstName", `${w}.identity`),
      lastName: optStr(identity, "lastName", `${w}.identity`),
      email: optStr(identity, "email", `${w}.identity`),
      phone: optStr(identity, "phone", `${w}.identity`),
      username: optStr(identity, "username", `${w}.identity`),
    },
    // The fingerprint is `keyFingerprint` on the wire — and only that, see
    // crates/bw/src/model.rs.
    sshKey: ssh && {
      privateKey: optStr(ssh, "privateKey", `${w}.sshKey`),
      publicKey: optStr(ssh, "publicKey", `${w}.sshKey`),
      fingerprint: optStr(ssh, "keyFingerprint", `${w}.sshKey`) ?? optStr(ssh, "fingerprint", `${w}.sshKey`),
    },
  };
}

/// Reads the answer's text. It must be an object: every list in it may be
/// empty, so only this check tells an empty vault from somebody else's page
/// (a proxy's error, a login portal).
export function parseSync(body: string): SyncData {
  if (!body.trimStart().startsWith("{")) return bad("notAnObject");
  let v: Json;
  try {
    v = JSON.parse(body);
  } catch {
    return bad("json");
  }
  if (!isObj(v)) return bad("notAnObject");
  const p = objOrNull(v, "profile", "sync") ?? bad("sync.profile");
  return {
    profile: {
      id: reqStr(p, "id", "profile"),
      email: reqStr(p, "email", "profile"),
      name: optStr(p, "name", "profile"),
      key: optStr(p, "key", "profile"),
      privateKey: optStr(p, "privateKey", "profile"),
      organizations: each(list(p, "organizations", "profile"), "profile.organizations", readOrg),
    },
    folders: each(list(v, "folders", "sync"), "folders", (f, w) => ({ id: reqStr(f, "id", w), name: reqStr(f, "name", w) })),
    collections: each(list(v, "collections", "sync"), "collections", (c, w) => ({
      id: reqStr(c, "id", w),
      name: reqStr(c, "name", w),
      organizationId: reqStr(c, "organizationId", w),
      readOnly: bool(c, "readOnly", w),
    })),
    ciphers: each(list(v, "ciphers", "sync"), "ciphers", readCipher),
  };
}
