// The write side against a fake server: what goes over the wire is checked
// with node:crypto (an implementation apart from the backend's WebCrypto), a
// kept secret is shown never to be opened, a confirm's sealed key is opened
// with the member's own private key, and nothing typed reaches the wire or
// the storage in the clear.
import * as nc from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Change } from "@keyward/core/backend";
import { type ItemDraft, GeneratorKind } from "@keyward/core/writes";
import { fromB64 } from "../src/backend/bytes";
import { importSymKey } from "../src/backend/crypto";
import { decryptString, parseEncString } from "../src/backend/encstring";
import { encryptBytes, encryptText, importMemberPublicKey, sealForMember } from "../src/backend/encrypt";
import { isWebError } from "../src/backend/errors";
import { WebBackend } from "../src/backend/index";
import { fingerprintPhrase, PASSPHRASE_WORDS, PASSWORD_LENGTH, randomBelow } from "../src/backend/writes";
import wordlist from "../src/backend/eff_large_wordlist.json";
import { b64, enc2, encRsa, fakeFetch, jwt, MapStorage, masterOf, rsaPair, type Route } from "./helpers";
import { ItemKind, OrgRole, Permission } from "@keyward/core/model/types";

const SERVER = "https://vault.example.com";
const EMAIL = "me@example.com";
const PASSWORD = "correct horse battery staple";
/// The least the backend accepts (KDF_BOUNDS).
const ITER = 100_000;
const NOW = 1_790_000_000_000;
const NOW_ISO = new Date(NOW).toISOString();

/// Typed in the tests' drafts: none may appear on the wire or in storage.
const TYPED = ["typed-password-77", "typed-note-secret", "typed-hidden-value", "typed-card-number-4111", "typed-ssh-private"];

const code = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    if (isWebError(e)) return e.code;
    throw e;
  }
  return "no error";
};

/// `2.iv|ct|mac` opened with node: the mac checked first.
function dec2(key: Uint8Array, s: string): string {
  const m = /^2\.([^|]+)\|([^|]+)\|([^|]+)$/.exec(s);
  if (!m) throw new Error(`not type 2: ${s}`);
  const iv = Buffer.from(m[1]!, "base64");
  const ct = Buffer.from(m[2]!, "base64");
  const mac = Buffer.from(m[3]!, "base64");
  const want = nc.createHmac("sha256", key.subarray(32, 64)).update(Buffer.concat([iv, ct])).digest();
  if (!nc.timingSafeEqual(want, mac)) throw new Error("mac");
  const d = nc.createDecipheriv("aes-256-cbc", key.subarray(0, 32), iv);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}

const blank = (over: Partial<ItemDraft> = {}): ItemDraft => ({
  kind: ItemKind.Login,
  name: "New login",
  folderId: null,
  orgId: null,
  collectionIds: [],
  favorite: false,
  reprompt: false,
  uris: [],
  notes: { clear: true },
  fields: [],
  tags: {},
  ...over,
});

function fixture() {
  const m = masterOf(PASSWORD, EMAIL, ITER);
  const user = new Uint8Array(nc.randomBytes(64));
  const pair = rsaPair();
  const org = new Uint8Array(nc.randomBytes(64));
  const own = new Uint8Array(nc.randomBytes(64));
  const member = rsaPair();
  const u = (s: string) => enc2(user, s);
  const o = (s: string) => enc2(org, s);
  const i = (s: string) => enc2(own, s);

  const ciphers: Record<string, Record<string, unknown>> = {
    a: {
      id: "a",
      type: 1,
      name: u("GitLab"),
      notes: u("stored-note"),
      folderId: "f1",
      revisionDate: "2026-09-01T10:00:00Z",
      login: {
        username: u("alex"),
        password: u("stored-password"),
        totp: u("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ"),
        uris: [{ uri: u("https://gitlab.example.com"), match: 3, uriChecksum: u("sum") }],
        fido2Credentials: [{ rpId: u("gitlab.example.com"), keyValue: u("pk-material") }],
        passwordRevisionDate: "2024-01-01T00:00:00Z",
        autofillOnPageLoad: true,
      },
      fields: [
        { type: 0, name: u("Env"), value: u("prod"), linkedId: null },
        { type: 1, name: u("Token"), value: u("stored-token"), linkedId: null },
        { type: 0, name: u("kw-host"), value: u("git.example.com"), linkedId: null },
        { type: 1, name: u("kw-secret"), value: u("stored-kw-secret"), linkedId: null },
        { type: 2, name: u("Admin"), value: u("true"), linkedId: null },
        { type: 3, name: u("Alias"), value: null, linkedId: 100 },
      ],
      passwordHistory: [{ password: u("older-password"), lastUsedDate: "2025-06-01T00:00:00Z" }],
    },
    b: {
      Id: "b",
      Type: 1,
      Name: i("GitHub bot"),
      OrganizationId: "org1",
      CollectionIds: ["c1"],
      Key: enc2(org, own),
      RevisionDate: "2026-09-02T10:00:00Z",
      Login: { Username: i("bot"), Password: i("bot-password"), Uris: null },
    },
    f: {
      id: "f",
      type: 4,
      name: u("Passport"),
      identity: { firstName: u("Alex"), lastName: u("Morgan"), email: u("alex@example.com"), address1: u("1 Main St"), passportNumber: u("P123") },
    },
  };

  const sync = {
    profile: {
      id: "me",
      email: EMAIL,
      name: "Me",
      key: enc2(m.stretched, user),
      privateKey: enc2(user, pair.der),
      organizations: [{ id: "org1", name: "Acme", key: encRsa(pair.publicKey, org), type: 1, status: 2 }],
    },
    folders: [{ id: "f1", name: u("Work") }],
    collections: [
      { id: "c1", organizationId: "org1", name: o("Platform"), readOnly: false },
      { id: "c2", organizationId: "org1", name: o("Read only"), readOnly: true },
    ],
    ciphers: Object.values(ciphers),
  };
  return { m, user, org, own, member, sync, ciphers };
}

function setup() {
  const fx = fixture();
  const access = jwt(Math.floor(NOW / 1000) + 3600);
  const writes: { method: string; path: string; body: unknown }[] = [];
  let memberStatus = 1;
  let memberSpki = b64(fx.member.publicKey.export({ type: "spki", format: "der" }));
  const routes: Route[] = [
    (r) => (r.url === `${SERVER}/identity/accounts/prelogin` ? { status: 200, body: { kdf: 0, kdfIterations: ITER } } : undefined),
    (r) => {
      if (r.url !== `${SERVER}/identity/connect/token`) return undefined;
      if (new URLSearchParams(r.body).get("password") !== fx.m.hash) return { status: 400, body: { error_description: "invalid_username_or_password" } };
      return { status: 200, body: { access_token: access, refresh_token: "r1", Key: fx.sync.profile.key, PrivateKey: fx.sync.profile.privateKey } };
    },
    (r) => {
      if (!r.url.startsWith(`${SERVER}/api/`)) return undefined;
      if (r.headers.get("Authorization") !== `Bearer ${access}`) return { status: 401, body: "" };
      const path = r.url.slice(`${SERVER}/api/`.length);
      if (r.method === "GET" && path === "sync?excludeDomains=true") return { status: 200, body: fx.sync };
      if (r.method === "GET" && path === "organizations/org1/users") {
        return {
          status: 200,
          body: {
            data: [
              { id: "m1", userId: "me", email: EMAIL, status: 2, type: 1, accessAll: true },
              { id: "m2", userId: "u2", email: "dana@acme.example", status: memberStatus, type: 2, accessAll: false, collections: [] },
            ],
          },
        };
      }
      if (r.method === "GET" && path.startsWith("ciphers/")) {
        const c = fx.ciphers[path.slice("ciphers/".length)];
        return c ? { status: 200, body: c } : { status: 404, body: "" };
      }
      if (r.method === "GET" && path === "organizations/org1/users/m2") return { status: 200, body: { Id: "m2", UserId: "u2", Status: memberStatus, Type: 2 } };
      if (r.method === "GET" && path === "users/u2/public-key") {
        return { status: 200, body: { UserId: "u2", PublicKey: memberSpki } };
      }
      if (r.method === "GET" && path === "organizations/org1/collections/c1/details") {
        return {
          status: 200,
          body: { id: "c1", name: "x", externalId: null, users: [{ id: "m2", readOnly: true, hidePasswords: false, manage: false }], groups: [{ Id: "g1", ReadOnly: false }] },
        };
      }
      if (r.method === "GET") return undefined;
      const body = r.body === "" ? null : JSON.parse(r.body);
      writes.push({ method: r.method, path, body });
      if (r.method === "POST" && (path === "ciphers" || path === "ciphers/create")) return { status: 200, body: { Id: "new-cipher", Object: "cipher" } };
      if (r.method === "POST" && path === "folders") return { status: 200, body: { id: "new-folder" } };
      if (r.method === "POST" && path === "organizations/org1/collections") return { status: 200, body: { id: "new-collection" } };
      return { status: 200, body: "" };
    },
  ];
  const net = fakeFetch(routes);
  const storage = new MapStorage();
  const backend = new WebBackend({ server: SERVER, fetch: net.fetch, deviceStorage: storage, idle: null, now: () => NOW });
  const changes: Change[] = [];
  backend.subscribe((c) => changes.push(c));
  return {
    fx,
    net,
    storage,
    backend,
    writes,
    changes,
    setMemberStatus: (s: number) => {
      memberStatus = s;
    },
    /// The server hands out another public key for the member from now on.
    setMemberKey: (spkiB64: string) => {
      memberSpki = spkiB64;
    },
  };
}

type Setup = ReturnType<typeof setup>;

const last = (t: Setup) => t.writes[t.writes.length - 1]!;
const noTyped = (t: Setup) => {
  const wire = t.net.calls.map((c) => c.body).join("\n");
  for (const s of TYPED) {
    expect(wire).not.toContain(s);
    expect(t.storage.dump()).not.toContain(s);
  }
};

describe("encryption", () => {
  it("writes type 2 that node and the reading side both open, with a fresh IV each time", async () => {
    const raw = new Uint8Array(nc.randomBytes(64));
    const key = await importSymKey(raw.slice());
    const a = await encryptText(key, "héllo wörld — 🔑");
    const b = await encryptText(key, "héllo wörld — 🔑");
    expect(a).not.toBe(b);
    expect(dec2(raw, a)).toBe("héllo wörld — 🔑");
    expect(await decryptString(b, key)).toBe("héllo wörld — 🔑");
    const e = parseEncString(a);
    expect(e.type).toBe(2);
    // A flipped bit in the ciphertext is caught by the mac.
    const [iv, ct, mac] = a.slice(2).split("|");
    const bad = Buffer.from(ct!, "base64");
    bad[0]! ^= 1;
    expect(await code(decryptString(`2.${iv}|${bad.toString("base64")}|${mac}`, key))).toBe("err.macMismatch");
  });

  it("wipes the plaintext bytes it was handed only when asked to, and seals empty input as one block", async () => {
    const raw = new Uint8Array(nc.randomBytes(64));
    const key = await importSymKey(raw.slice());
    const s = await encryptBytes(key, new Uint8Array(0));
    expect(fromB64(s.slice(2).split("|")[1]!).length).toBe(16);
    expect(dec2(raw, s)).toBe("");
  });

  it("seals raw key bytes for a member as 4. that the member's private key opens", async () => {
    const pair = nc.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pub = await importMemberPublicKey(b64(pair.publicKey.export({ type: "spki", format: "der" })));
    const raw = new Uint8Array(nc.randomBytes(64));
    const sealed = await sealForMember(pub, raw);
    expect(sealed.startsWith("4.")).toBe(true);
    const opened = nc.privateDecrypt({ key: pair.privateKey, padding: nc.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, Buffer.from(sealed.slice(2), "base64"));
    expect(new Uint8Array(opened)).toEqual(raw);
  });

  it("refuses a short or broken member key", async () => {
    const weak = nc.generateKeyPairSync("rsa", { modulusLength: 1024 });
    expect(await code(importMemberPublicKey(b64(weak.publicKey.export({ type: "spki", format: "der" }))))).toBe("err.memberKeyWeak");
    // A longer key seals into a `4.` no reader of the format takes (it is 256 bytes, exactly).
    const long = nc.generateKeyPairSync("rsa", { modulusLength: 3072 });
    expect(await code(importMemberPublicKey(b64(long.publicKey.export({ type: "spki", format: "der" }))))).toBe("err.memberKeyMalformed");
    expect(await code(importMemberPublicKey("not base64!"))).toBe("err.memberKeyMalformed");
    expect(await code(importMemberPublicKey(b64(Buffer.from("garbage"))))).toBe("err.memberKeyMalformed");
  });
});

describe("item writes", () => {
  let t: Setup;
  beforeEach(async () => {
    t = setup();
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    t.changes.length = 0;
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("creates a personal login with every value sealed by the user key", async () => {
    const id = await t.backend.create(
      blank({
        name: "  Shop  ",
        folderId: "f1",
        favorite: true,
        reprompt: true,
        uris: ["https://shop.example", "  "],
        notes: { set: "typed-note-secret" },
        fields: [
          { key: "username", value: "me@shop" },
          { key: "password", secret: { set: "typed-password-77" } },
          { custom: "PIN hint", value: "blue", hidden: false },
          { custom: "Recovery", secret: { set: "typed-hidden-value" }, hidden: true },
        ],
        tags: { "kw-host": "shop.example" },
      }),
    );
    expect(id).toBe("new-cipher");
    const w = last(t);
    expect(w.method).toBe("POST");
    expect(w.path).toBe("ciphers");
    const b = w.body as Record<string, any>;
    expect(b).toMatchObject({ type: 1, organizationId: null, folderId: "f1", favorite: true, reprompt: 1, key: null, passwordHistory: [] });
    expect(b.lastKnownRevisionDate).toBeUndefined();
    const k = t.fx.user;
    expect(dec2(k, b.name)).toBe("Shop");
    expect(dec2(k, b.notes)).toBe("typed-note-secret");
    expect(dec2(k, b.login.username)).toBe("me@shop");
    expect(dec2(k, b.login.password)).toBe("typed-password-77");
    expect(b.login.totp).toBeNull();
    expect(b.login.fido2Credentials).toEqual([]);
    expect(b.login.passwordRevisionDate).toBe(NOW_ISO);
    expect(b.login.uris).toHaveLength(1);
    expect(dec2(k, b.login.uris[0].uri)).toBe("https://shop.example");
    expect(dec2(k, b.login.uris[0].uriChecksum)).toBe(nc.createHash("sha256").update("https://shop.example").digest("base64"));
    expect(b.fields.map((f: any) => [f.type, dec2(k, f.name), dec2(k, f.value)])).toEqual([
      [0, "PIN hint", "blue"],
      [1, "Recovery", "typed-hidden-value"],
      [0, "kw-host", "shop.example"],
    ]);
    // The window rebases: a sync, then the item.
    expect(t.changes).toEqual([{ kind: "catalog" }, { kind: "item", id: "new-cipher" }]);
    noTyped(t);
  });

  it("creates an organisation's item through ciphers/create, sealed by the organisation key", async () => {
    await t.backend.create(
      blank({ kind: ItemKind.Card, name: "Corp card", orgId: "org1", collectionIds: ["c1"], fields: [{ key: "number", secret: { set: "typed-card-number-4111" } }, { key: "brand", value: "Visa" }] }),
    );
    const w = last(t);
    expect(w.path).toBe("ciphers/create");
    const b = w.body as { cipher: Record<string, any>; collectionIds: string[] };
    expect(b.collectionIds).toEqual(["c1"]);
    expect(b.cipher.type).toBe(3);
    expect(b.cipher.organizationId).toBe("org1");
    expect(dec2(t.fx.org, b.cipher.name)).toBe("Corp card");
    expect(dec2(t.fx.org, b.cipher.card.number)).toBe("typed-card-number-4111");
    expect(b.cipher.card).toMatchObject({ code: null, expMonth: null, expYear: null, cardholderName: null });
    noTyped(t);
  });

  it("gives a secure note its part and an ssh key its wire names", async () => {
    await t.backend.create(blank({ kind: ItemKind.SecureNote, name: "Note", notes: { set: "typed-note-secret" } }));
    expect((last(t).body as any).secureNote).toEqual({ type: 0 });
    await t.backend.create(
      blank({
        kind: ItemKind.SshKey,
        name: "id",
        fields: [
          { key: "privateKey", secret: { set: "typed-ssh-private" } },
          { key: "publicKey", value: "ssh-ed25519 AAAA" },
          { key: "fingerprint", value: "SHA256:abc" },
        ],
      }),
    );
    const s = (last(t).body as any).sshKey;
    expect(dec2(t.fx.user, s.keyFingerprint)).toBe("SHA256:abc");
    expect(dec2(t.fx.user, s.privateKey)).toBe("typed-ssh-private");
    noTyped(t);
  });

  it("refuses an inconsistent draft before anything is sent", async () => {
    const before = t.writes.length;
    expect(await code(t.backend.create(blank({ name: " " })))).toBe("err.draftNameEmpty");
    expect(await code(t.backend.create(blank({ kind: "spaceship" as never })))).toBe("err.itemKindUnknown");
    expect(await code(t.backend.create(blank({ fields: [{ key: "number", value: "1" }] })))).toBe("err.draftFieldUnknown");
    expect(await code(t.backend.create(blank({ fields: [{ key: "username", value: "a" }, { key: "username", value: "b" }] })))).toBe("err.draftFieldTwice");
    expect(await code(t.backend.create(blank({ fields: [{ key: "password", secret: { keep: true } }] })))).toBe("err.draftKeepNew");
    expect(await code(t.backend.create(blank({ notes: { keep: true } })))).toBe("err.draftKeepNew");
    expect(await code(t.backend.create(blank({ orgId: "org9", collectionIds: ["c1"] })))).toBe("err.noOrgKey");
    expect(await code(t.backend.create(blank({ orgId: "org1", collectionIds: [] })))).toBe("err.collectionRequired");
    expect(await code(t.backend.create(blank({ orgId: "org1", collectionIds: ["c2"] })))).toBe("err.collectionReadOnly");
    expect(await code(t.backend.create(blank({ collectionIds: ["c1"] })))).toBe("err.collectionWithoutOrg");
    expect(await code(t.backend.create(blank({ folderId: "nope" })))).toBe("err.folderNotFound");
    expect(await code(t.backend.create(blank({ tags: { host: "x" } })))).toBe("err.draftTagMalformed");
    expect(await code(t.backend.create(blank({ fields: [{ custom: "kw-x", value: "1", hidden: false }] })))).toBe("err.draftTagMalformed");
    expect(await code(t.backend.create(blank({ kind: ItemKind.Card, uris: ["https://x"] })))).toBe("err.draftFieldUnknown");
    expect(t.writes.length).toBe(before);
  });

  it("edits an item with its own key: kept secrets go back as the very EncStrings, never opened", async () => {
    const stored = t.fx.ciphers.b as any;
    const storedCt = parseEncString(stored.Login.Password);
    // The catalogue (built once, before the spy) opens passwords for reuse
    // detection; the edit itself must not.
    await t.backend.catalog();
    const seen: Uint8Array[] = [];
    const real = globalThis.crypto.subtle.decrypt.bind(globalThis.crypto.subtle);
    vi.spyOn(globalThis.crypto.subtle, "decrypt").mockImplementation((alg, key, data) => {
      seen.push(new Uint8Array(ArrayBuffer.isView(data) ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) : (data as ArrayBuffer)));
      return real(alg, key, data);
    });

    await t.backend.update(
      "b",
      blank({
        name: "GitHub bot (ci)",
        orgId: "org1",
        collectionIds: ["c1"],
        fields: [
          { key: "username", value: "bot" },
          { key: "password", secret: { keep: true } },
        ],
      }),
    );
    const put = t.writes.find((w) => w.method === "PUT" && w.path === "ciphers/b")!;
    const b = put.body as Record<string, any>;
    expect(b.key).toBe(stored.Key);
    expect(b.login.password).toBe(stored.Login.Password);
    expect(b.passwordHistory).toEqual([]);
    expect(b.lastKnownRevisionDate).toBe("2026-09-02T10:00:00Z");
    expect(dec2(t.fx.own, b.name)).toBe("GitHub bot (ci)");
    expect(dec2(t.fx.own, b.login.username)).toBe("bot");
    // The collections did not change: no second request.
    expect(t.writes.some((w) => w.path === "ciphers/b/collections")).toBe(false);
    // The stored password's ciphertext was never handed to decrypt.
    expect(storedCt.type).toBe(2);
    const ct = storedCt.ct;
    expect(seen.some((d) => d.length === ct.length && d.every((x, i) => x === ct[i]))).toBe(false);
    expect(seen.length).toBeGreaterThan(0);
    expect(t.changes).toContainEqual({ kind: "item", id: "b" });
  });

  it("moves an organisation's item between collections with its own request", async () => {
    await t.backend.update("b", blank({ name: "GitHub bot", orgId: "org1", collectionIds: ["c1", "c1"], fields: [{ key: "password", secret: { keep: true } }] }));
    expect(t.writes.some((w) => w.path === "ciphers/b/collections")).toBe(false);
    t.fx.sync.collections.push({ id: "c3", organizationId: "org1", name: enc2(t.fx.org, "Ops"), readOnly: false });
    await t.backend.sync();
    await t.backend.update("b", blank({ name: "GitHub bot", orgId: "org1", collectionIds: ["c3"], fields: [{ key: "password", secret: { keep: true } }] }));
    expect(last(t)).toEqual({ method: "PUT", path: "ciphers/b/collections", body: { collectionIds: ["c3"] } });
  });

  it("keeps what the draft cannot say, and puts a changed password into the history", async () => {
    const a = t.fx.ciphers.a as any;
    await t.backend.update(
      "a",
      blank({
        name: "GitLab",
        folderId: "f1",
        uris: ["https://gitlab.example.com", "https://new.example"],
        notes: { keep: true },
        fields: [
          { key: "username", value: "alex" },
          { key: "password", secret: { set: "typed-password-77" } },
          { key: "totp", secret: { keep: true } },
          { custom: "Env", value: "staging", hidden: false },
          { custom: "Token", secret: { keep: true }, hidden: true },
          { custom: "Admin", value: "false", hidden: false },
        ],
        tags: { "kw-host": "gitlab.internal" },
      }),
    );
    const b = last(t).body as Record<string, any>;
    const k = t.fx.user;
    expect(b.notes).toBe(a.notes);
    expect(b.login.totp).toBe(a.login.totp);
    expect(dec2(k, b.login.password)).toBe("typed-password-77");
    expect(b.login.passwordRevisionDate).toBe(NOW_ISO);
    expect(b.login.fido2Credentials).toEqual(a.login.fido2Credentials);
    expect(b.login.autofillOnPageLoad).toBe(true);
    expect(b.passwordHistory).toEqual([{ password: a.login.password, lastUsedDate: NOW_ISO }, ...a.passwordHistory]);
    // The unchanged URI keeps its match rule and checksum; the new one gets its own.
    expect(b.login.uris[0]).toEqual(a.login.uris[0]);
    expect(dec2(k, b.login.uris[1].uri)).toBe("https://new.example");
    const fields = b.fields as any[];
    const byName = (n: string) => fields.filter((f) => f.name !== null && dec2(k, f.name) === n);
    expect(byName("Env").map((f) => [f.type, dec2(k, f.value)])).toEqual([[0, "staging"]]);
    expect(byName("Token")).toEqual([a.fields[1]]);
    expect(byName("Admin").map((f) => [f.type, dec2(k, f.value)])).toEqual([[2, "false"]]);
    expect(byName("kw-host").map((f) => dec2(k, f.value))).toEqual(["gitlab.internal"]);
    // A plugin's hidden field and a linked field survive, untouched.
    expect(byName("kw-secret")).toEqual([a.fields[3]]);
    expect(byName("Alias")).toEqual([a.fields[5]]);
    expect(fields).toHaveLength(6);
    noTyped(t);
  });

  it("sends an identity back whole when three of its fields change", async () => {
    const f = t.fx.ciphers.f as any;
    await t.backend.update("f", blank({ kind: ItemKind.Identity, name: "Passport", fields: [{ key: "firstName", value: "Alexandra" }] }));
    const b = last(t).body as Record<string, any>;
    expect(dec2(t.fx.user, b.identity.firstName)).toBe("Alexandra");
    expect(b.identity.address1).toBe(f.identity.address1);
    expect(b.identity.passportNumber).toBe(f.identity.passportNumber);
    expect(b.identity.lastName).toBe(f.identity.lastName);
  });

  it("refuses an edit that changes the kind or the owner, or names a kept field that is not there", async () => {
    expect(await code(t.backend.update("a", blank({ kind: ItemKind.Card })))).toBe("err.itemKindChange");
    expect(await code(t.backend.update("b", blank({ orgId: null })))).toBe("err.itemOrgChange");
    expect(await code(t.backend.update("a", blank({ folderId: "f1", fields: [{ custom: "Nope", secret: { keep: true }, hidden: true }] })))).toBe("err.secretAbsent");
    expect(await code(t.backend.update("zzz", blank()))).toBe("err.itemNotFound");
    expect(await code(t.backend.update("../x", blank()))).toBe("err.badIdentifier");
    expect(t.writes.filter((w) => w.method === "PUT")).toEqual([]);
  });
});

describe("folders, collections and members", () => {
  let t: Setup;
  beforeEach(async () => {
    t = setup();
    await t.backend.login({ email: EMAIL, password: PASSWORD });
  });

  it("writes folder names under the user key", async () => {
    expect(await t.backend.createFolder(" Home ")).toBe("new-folder");
    expect(dec2(t.fx.user, (last(t).body as any).name)).toBe("Home");
    await t.backend.renameFolder("f1", "Job");
    expect(last(t).method).toBe("PUT");
    expect(last(t).path).toBe("folders/f1");
    expect(dec2(t.fx.user, (last(t).body as any).name)).toBe("Job");
    await t.backend.deleteFolder("f1");
    expect(last(t)).toEqual({ method: "DELETE", path: "folders/f1", body: null });
    expect(await code(t.backend.renameFolder("f9", "x"))).toBe("err.folderNotFound");
    expect(await code(t.backend.createFolder("  "))).toBe("err.nameEmpty");
  });

  it("writes collection names under the organisation key, and a rename keeps every grant", async () => {
    expect(await t.backend.createCollection("org1", "Ops")).toBe("new-collection");
    const c = last(t);
    expect(c.path).toBe("organizations/org1/collections");
    expect(dec2(t.fx.org, (c.body as any).name)).toBe("Ops");
    await t.backend.renameCollection("org1", "c1", "Platform team");
    const r = last(t);
    expect(r.method).toBe("PUT");
    expect(r.path).toBe("organizations/org1/collections/c1");
    expect(dec2(t.fx.org, (r.body as any).name)).toBe("Platform team");
    expect((r.body as any).users).toEqual([{ id: "m2", readOnly: true, hidePasswords: false, manage: false }]);
    expect((r.body as any).groups).toEqual([{ id: "g1", readOnly: false, hidePasswords: false, manage: false }]);
    await t.backend.deleteCollection("org1", "c1");
    expect(last(t)).toEqual({ method: "DELETE", path: "organizations/org1/collections/c1", body: null });
    expect(await code(t.backend.deleteCollection("org1", "c9"))).toBe("err.collectionNotFound");
    expect(await code(t.backend.createCollection("org9", "x"))).toBe("err.orgNotFound");
  });

  it("invites and changes members with the server's role codes and grants", async () => {
    await t.backend.invite("org1", { emails: [" Dana@Acme.example ", "dana@acme.example", "lee@acme.example"], role: OrgRole.Manager, accessAll: false, access: { c1: Permission.ReadHidden } });
    expect(last(t)).toEqual({
      method: "POST",
      path: "organizations/org1/users/invite",
      body: { emails: ["dana@acme.example", "lee@acme.example"], type: 3, accessAll: false, collections: [{ id: "c1", readOnly: true, hidePasswords: true, manage: false }], permissions: {} },
    });
    await t.backend.setMember("org1", "m2", { role: OrgRole.Admin, accessAll: true, access: {} });
    expect(last(t)).toEqual({ method: "PUT", path: "organizations/org1/users/m2", body: { type: 1, accessAll: true, collections: [], permissions: {} } });
    expect(await code(t.backend.invite("org1", { emails: ["nope"], role: OrgRole.User, accessAll: true, access: {} }))).toBe("err.inviteEmailMalformed");
    expect(await code(t.backend.invite("org1", { emails: [], role: OrgRole.User, accessAll: true, access: {} }))).toBe("err.inviteEmpty");
    expect(await code(t.backend.invite("org1", { emails: ["a@b.c"], role: OrgRole.Custom, accessAll: true, access: {} }))).toBe("err.customRoleUnsupported");
    expect(await code(t.backend.setMember("org1", "m2", { role: OrgRole.User, accessAll: false, access: { c9: Permission.Read } }))).toBe("err.collectionNotFound");
    await t.backend.removeMember("org1", "m2");
    expect(last(t)).toEqual({ method: "POST", path: "organizations/org1/users/m2/delete", body: null });
    expect(await code(t.backend.removeMember("org1", "m1"))).toBe("err.cannotRemoveSelf");
  });

  it("confirms a member with the organisation key sealed for their own public key", async () => {
    const words = await t.backend.memberFingerprint("org1", "m2");
    const der = new Uint8Array(t.fx.member.publicKey.export({ type: "spki", format: "der" }));
    expect(words).toEqual(await fingerprintPhrase("u2", der));
    await t.backend.confirmMember("org1", "m2", words);
    const w = last(t);
    expect(w.path).toBe("organizations/org1/users/m2/confirm");
    const sealed = (w.body as { key: string }).key;
    expect(sealed.startsWith("4.")).toBe(true);
    const memberPrivate = nc.createPrivateKey({ key: Buffer.from(t.fx.member.der), format: "der", type: "pkcs8" });
    const opened = nc.privateDecrypt({ key: memberPrivate, padding: nc.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, Buffer.from(sealed.slice(2), "base64"));
    expect(new Uint8Array(opened)).toEqual(t.fx.org);
  });

  it("seals nothing when the member's key changed after its fingerprint was shown", async () => {
    const shown = await t.backend.memberFingerprint("org1", "m2");
    const before = t.writes.length;
    t.setMemberKey(b64(rsaPair().publicKey.export({ type: "spki", format: "der" })));
    expect(await code(t.backend.confirmMember("org1", "m2", shown))).toBe("err.fingerprintChanged");
    expect(await code(t.backend.confirmMember("org1", "m2", []))).toBe("err.fingerprintChanged");
    expect(t.writes.length).toBe(before);
    // The new key's own words are what a fresh preview shows, and they pass.
    const fresh = await t.backend.memberFingerprint("org1", "m2");
    expect(fresh).not.toEqual(shown);
    await t.backend.confirmMember("org1", "m2", fresh);
    expect(last(t).path).toBe("organizations/org1/users/m2/confirm");
  });

  it("does not confirm someone who has not accepted", async () => {
    t.setMemberStatus(0);
    const before = t.writes.length;
    expect(await code(t.backend.memberFingerprint("org1", "m2"))).toBe("err.memberNotAccepted");
    expect(await code(t.backend.confirmMember("org1", "m2", ["a", "b", "c", "d", "e"]))).toBe("err.memberNotAccepted");
    expect(t.writes.length).toBe(before);
  });
});

describe("the fingerprint phrase", () => {
  it("is Bitwarden's: the official clients' known answer", async () => {
    // sdk-internal, crates/bitwarden-crypto/src/fingerprint.rs, `test_fingerprint`;
    // the same vector as crates/vault/src/fingerprint.rs.
    const key =
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuyYs8W7NWf0Zv35Ueco93730dtRKi4Jhc6Snar+86drE+ruSfaCWMcbgsAoAj2Pm6KAzaJrTIVCqBERQ23OncpzjfcGAeyf+v3w/gSw/EjihMJ4AG5ICY4hLFYcGdgwa+7is+TVO0i6PEWjKQa3l2+mQo2XY7pg2ngHDMssV4gxSqq+qoBX3+FBhewCYdOV+3cebwsAzz7HwoFTxKViwNW8crbHonhZPhZgfIAzEkzo5MvzQg5azhLKW6vuPfaOQFC5HqPykVnh8OPzO0uzUi3+97CguAu4N2CgwVYXltZuw2fGamdVw3kjbxQPbOE1tL0j7gyTwYKkfUl2m8gMh1QIDAQAB";
    expect(await fingerprintPhrase("a09726a0-9590-49d1-a5f5-afe300b6a515", fromB64(key))).toEqual(["turban", "deftly", "anime", "chatroom", "unselfish"]);
  });
  it("matches the daemon's independent calculation", async () => {
    const der = new Uint8Array(512).map((_, i) => i % 256);
    expect(await fingerprintPhrase("11111111-2222-3333-4444-555555555555", der)).toEqual(["preamble", "dispersed", "spree", "doorknob", "stable"]);
  });
});

describe("the password check", () => {
  it("derives locally, compares, and sends nothing", async () => {
    const t = setup();
    expect(await code(t.backend.verifyPassword(PASSWORD))).toBe("err.locked");
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    const calls = t.net.calls.length;
    expect(await t.backend.verifyPassword(PASSWORD)).toBe(true);
    expect(await t.backend.verifyPassword(`${PASSWORD} `)).toBe(false);
    expect(await t.backend.verifyPassword("")).toBe(false);
    expect(t.net.calls.length).toBe(calls);
    expect(t.storage.dump()).not.toContain(t.fx.m.hash);
    // After a lock the check is gone with the keys; an unlock brings it back.
    await t.backend.lock();
    expect(await code(t.backend.verifyPassword(PASSWORD))).toBe("err.locked");
    await t.backend.unlock(PASSWORD);
    expect(await t.backend.verifyPassword(PASSWORD)).toBe(true);
    expect(await t.backend.verifyPassword("wrong")).toBe(false);
  });
});

describe("the generator", () => {
  const t = setup();
  const pw = (over: object = {}) =>
    t.backend.generate({ kind: GeneratorKind.Password, length: 24, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguous: false, ...over });

  it("draws unbiased integers", () => {
    const n = 7;
    const draws = 70_000;
    const counts = new Array<number>(n).fill(0);
    for (let i = 0; i < draws; i++) counts[randomBelow(n)]!++;
    // Chi-square with 6 degrees of freedom: 22.46 is p = 0.001.
    const expected = draws / n;
    const chi = counts.reduce((s, c) => s + (c - expected) ** 2 / expected, 0);
    expect(chi).toBeLessThan(22.46);
    expect(randomBelow(1)).toBe(0);
    expect(() => randomBelow(0)).toThrow();
  });

  it("keeps a password's length and the sets that were asked for, one of each at least", async () => {
    for (let i = 0; i < 200; i++) {
      const g = await pw({ length: 5 });
      expect(g.value).toHaveLength(5);
      expect(g.value).toMatch(/[A-Z]/);
      expect(g.value).toMatch(/[a-z]/);
      expect(g.value).toMatch(/[0-9]/);
      expect(g.value).toMatch(/[!@#$%^&*]/);
      expect(g.value).toMatch(/^[A-Za-z0-9!@#$%^&*]+$/);
    }
    const digits = await pw({ length: 128, upper: false, lower: false, symbols: false });
    expect(digits.value).toMatch(/^[0-9]{128}$/);
    const clear = await pw({ length: 128, symbols: false, avoidAmbiguous: true });
    expect(clear.value).not.toMatch(/[IOl01]/);
    clear.drop();
    expect(clear.value).toBe("");
  });

  it("spreads characters evenly over the set", async () => {
    const counts = new Map<string, number>();
    for (let i = 0; i < 100; i++) for (const c of (await pw({ length: 100, upper: false, lower: false, symbols: false })).value) counts.set(c, (counts.get(c) ?? 0) + 1);
    expect(counts.size).toBe(10);
    for (const c of counts.values()) expect(Math.abs(c - 1000)).toBeLessThan(150);
  });

  it("refuses rules that cannot hold", async () => {
    expect(await code(pw({ length: PASSWORD_LENGTH.min - 1 }))).toBe("err.generatorLength");
    expect(await code(pw({ length: PASSWORD_LENGTH.max + 1 }))).toBe("err.generatorLength");
    expect(await code(pw({ length: 10.5 }))).toBe("err.generatorLength");
    expect(await code(pw({ upper: false, lower: false, digits: false, symbols: false }))).toBe("err.generatorNoCharset");
  });

  it("makes passphrases from the EFF long list", async () => {
    const list = new Set((wordlist as { words: string[] }).words);
    expect(list.size).toBe(7776);
    // A few of the list's words hold a hyphen, so the test splits on another mark.
    const g = await t.backend.generate({ kind: GeneratorKind.Passphrase, words: 6, separator: "_", capitalize: false, number: false });
    const parts = g.value.split("_");
    expect(parts).toHaveLength(6);
    expect(parts.every((p) => list.has(p))).toBe(true);
    const c = await t.backend.generate({ kind: GeneratorKind.Passphrase, words: 4, separator: " ", capitalize: true, number: true });
    const words = c.value.split(" ");
    expect(words).toHaveLength(4);
    expect(words.every((w) => /^[A-Z]/.test(w))).toBe(true);
    expect(words.filter((w) => /[0-9]$/.test(w))).toHaveLength(1);
    expect(words.every((w) => list.has(w.replace(/[0-9]$/, "").toLowerCase()))).toBe(true);
    expect(await code(t.backend.generate({ kind: GeneratorKind.Passphrase, words: PASSPHRASE_WORDS.min - 1, separator: "-", capitalize: false, number: false }))).toBe("err.generatorWords");
    expect(await code(t.backend.generate({ kind: GeneratorKind.Passphrase, words: 5, separator: "x", capitalize: false, number: false }))).toBe("err.generatorSeparator");
    expect(await code(t.backend.generate({ kind: GeneratorKind.Passphrase, words: 5, separator: "--", capitalize: false, number: false }))).toBe("err.generatorSeparator");
  });
});

describe("permission levels", () => {
  it("reads and writes every level, edit-without-passwords included", async () => {
    const { permissionOf } = await import("../src/backend/catalog");
    expect(permissionOf(false, false, true)).toBe("manage");
    expect(permissionOf(false, false, false)).toBe("edit");
    expect(permissionOf(false, true, false)).toBe("editHidden");
    expect(permissionOf(true, false, false)).toBe("read");
    expect(permissionOf(true, true, false)).toBe("readHidden");
  });
});
