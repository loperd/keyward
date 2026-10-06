// The backend against a fake server: a vault encrypted with the tests' own
// keys (node:crypto), the login, the catalogue, the secrets and the session's
// life — and proof that nothing decrypted is kept where it must not be.
import * as nc from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { isWebError } from "../src/backend/errors";
import { WebBackend } from "../src/backend/index";
import type { IdleEnv } from "../src/backend/session";
import type { FocusEnv } from "../src/backend/clipboard";
import { b64, enc2, encRsa, FakeClipboard, fakeFetch, jwt, ManualTimers, MapStorage, masterOf, rsaPair, type Route } from "./helpers";
import { TwoFactorProvider } from "@keyward/core/backend";
import { SecretField, type SecretRef } from "@keyward/core/model/types";

const SERVER = "https://vault.example.com";
const EMAIL = "me@example.com";
const PASSWORD = "correct horse battery staple";
// The least PBKDF2 the backend accepts (KDF_BOUNDS).
const ITER = 100_000;
const NOW = 1_790_000_000_000;
const SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// Every plaintext secret of the fixture: none may appear where the window
/// or the storage can see it.
const SECRETS = [
  "same-secret",
  "own-secret",
  "trashed-secret",
  "hidden-token-value",
  "note-secret",
  "old-pass-value",
  "pk-secret-material",
  "4242 4242 4242 4242",
  "4242424242424242",
  "cvc-987",
  "openssh-secret-material",
  "service-root-token",
  "kw-secret-hidden-value",
  SEED,
  PASSWORD,
];

const code = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    if (isWebError(e)) return e.code;
    throw e;
  }
  return "no error";
};

function fixture() {
  const m = masterOf(PASSWORD, EMAIL, ITER);
  const user = new Uint8Array(nc.randomBytes(64));
  const pair = rsaPair();
  const org = new Uint8Array(nc.randomBytes(64));
  const org2 = new Uint8Array(nc.randomBytes(64));
  const own = new Uint8Array(nc.randomBytes(64));
  const u = (s: string) => enc2(user, s);
  const o = (s: string) => enc2(org, s);
  const i = (s: string) => enc2(own, s);

  const sync = {
    object: "sync",
    profile: {
      id: "me",
      email: EMAIL,
      name: "Me Myself",
      key: enc2(m.stretched, user),
      privateKey: enc2(user, pair.der),
      organizations: [
        { id: "org1", name: "Acme", key: encRsa(pair.publicKey, org), type: 1, status: 2, permissions: null },
        { Id: "org2", Name: "Globex", Key: encRsa(pair.publicKey, org2, true), Type: 4, Status: 2, Permissions: { manageUsers: false, editAnyCollection: true } },
      ],
    },
    folders: [{ id: "f1", name: u("Work") }],
    collections: [{ id: "c1", organizationId: "org1", name: o("Platform"), readOnly: false }],
    ciphers: [
      {
        id: "a",
        type: 1,
        name: u("GitLab"),
        folderId: "f1",
        notes: u("note-secret"),
        revisionDate: "2026-09-01T10:00:00Z",
        login: {
          username: u("alex"),
          password: u("same-secret"),
          totp: u(`otpauth://totp/GitLab:alex?secret=${SEED}`),
          uris: [{ uri: u("https://gitlab.example.com"), match: null }],
          passwordRevisionDate: "2024-01-01T00:00:00Z",
          fido2Credentials: [{ rpId: u("gitlab.example.com"), userName: u("alex"), keyValue: u("pk-secret-material"), creationDate: "2025-01-01" }],
        },
        fields: [
          { type: 0, name: u("Env"), value: u("prod") },
          { type: 1, name: u("Token"), value: u("hidden-token-value") },
          { type: 0, name: u("kw-host"), value: u("git.example.com") },
          { type: 1, name: u("kw-secret"), value: u("kw-secret-hidden-value") },
          { type: 2, name: u("Admin"), value: u("true") },
          { type: 3, name: u("Alias"), value: null, linkedId: 100 },
        ],
        passwordHistory: [{ password: u("old-pass-value"), lastUsedDate: "2025-06-01T00:00:00Z" }],
      },
      {
        id: "b",
        type: 1,
        name: i("GitHub bot"),
        organizationId: "org1",
        collectionIds: ["c1"],
        key: enc2(org, own),
        login: { username: i("bot"), password: i("same-secret"), uris: null },
      },
      { Id: "c", Type: 1, Name: u("Forum"), Login: { Username: u("me"), Password: u("own-secret") } },
      {
        id: "d",
        type: 3,
        name: u("Company card"),
        card: { cardholderName: u("Me"), number: u("4242 4242 4242 4242"), code: u("cvc-987"), brand: null, expMonth: u("9"), expYear: u("29") },
      },
      { id: "e", type: 5, name: u("id_ed25519"), sshKey: { keyFingerprint: u("SHA256:q3VbLx7c"), publicKey: u("ssh-ed25519 AAAA"), privateKey: u("openssh-secret-material") } },
      { id: "f", type: 4, name: u("Passport"), identity: { firstName: u("Alex"), lastName: u("Morgan"), email: u("alex@example.com") } },
      { id: "g", type: 2, name: u("root token"), notes: u("service-root-token"), fields: [{ type: 0, name: u("kw-hidden"), value: u("1") }] },
      { id: "h", type: 1, name: u("Old"), deletedDate: "2026-01-01T00:00:00Z", login: { password: u("same-secret"), username: u("old") } },
      { id: "t2", type: 1, name: u("Trashed alone"), deletedDate: "2026-01-02T00:00:00Z", login: { password: u("trashed-secret") } },
    ],
  };
  return { m, user, sync };
}

type ServerState = {
  access: string;
  refresh: string;
  twoFactor: boolean;
  newDevice: boolean;
  rememberToken: string | null;
  deleted: string[];
};

function server(fx: ReturnType<typeof fixture>, state: ServerState) {
  const form = (b: string) => Object.fromEntries(new URLSearchParams(b));
  const done = (extra: object = {}) => ({
    status: 200,
    body: { access_token: state.access, refresh_token: state.refresh, Key: fx.sync.profile.key, PrivateKey: fx.sync.profile.privateKey, Kdf: 0, ...extra },
  });
  const authed = (h: Headers) => h.get("Authorization") === `Bearer ${state.access}`;
  const routes: Route[] = [
    (r) => (r.url === `${SERVER}/identity/accounts/prelogin` ? { status: 200, body: { kdf: 0, kdfIterations: ITER, kdfMemory: null } } : undefined),
    (r) => {
      if (r.url !== `${SERVER}/identity/connect/token`) return undefined;
      const f = form(r.body);
      if (f.grant_type === "refresh_token") {
        if (f.refresh_token !== state.refresh) return { status: 400, body: { error: "invalid_grant" } };
        // Good for ten days: a test may move the clock past the first token.
        state.access = jwt(Math.floor(NOW / 1000) + 10 * 86400, "refreshed");
        state.refresh = `${state.refresh}+`;
        return { status: 200, body: { access_token: state.access, refresh_token: state.refresh } };
      }
      if (f.password !== fx.m.hash) {
        return { status: 400, body: { message: "Username or password is incorrect. Try again", errorModel: { message: "Username or password is incorrect. Try again" }, error: "" } };
      }
      if (state.newDevice) {
        if (f.newDeviceOtp === undefined) return { status: 400, body: { error: "invalid_grant", error_description: "New device verification required" } };
        if (f.newDeviceOtp !== "111111") return { status: 400, body: { error: "invalid_grant", error_description: "Invalid New Device OTP" } };
        return done();
      }
      if (state.twoFactor) {
        const ask = { status: 400, body: { error: "invalid_grant", error_description: "Two factor required.", TwoFactorProviders: ["0", "1"] } };
        if (f.twoFactorProvider === "5" && f.twoFactorToken === state.rememberToken) return done();
        if (f.twoFactorProvider !== "0" || f.twoFactorToken !== "123456") return ask;
        if (f.twoFactorRemember === "1") {
          state.rememberToken = "remember-me-token";
          return done({ TwoFactorToken: state.rememberToken });
        }
        return done();
      }
      return done();
    },
    (r) => {
      if (!r.url.startsWith(`${SERVER}/api/`)) return undefined;
      if (!authed(r.headers)) return { status: 401, body: "" };
      const path = r.url.slice(`${SERVER}/api/`.length);
      if (path === "sync?excludeDomains=true") return { status: 200, body: fx.sync };
      if (path === "organizations/org1/users") {
        return {
          status: 200,
          body: {
            data: [
              { id: "m1", userId: "me", name: "Me Myself", email: "ME@example.com", status: 2, type: 1, twoFactorEnabled: true, accessAll: true, collections: [] },
              { id: "m2", name: "dana@acme.example", email: "dana@acme.example", status: 1, type: 2, twoFactorEnabled: false, accessAll: false, collections: [{ id: "c1", readOnly: true, hidePasswords: false }] },
            ],
            object: "list",
          },
        };
      }
      if (r.method === "PUT" || r.method === "DELETE") {
        state.deleted.push(`${r.method} ${path} ${r.body}`);
        return { status: 200, body: "" };
      }
      return undefined;
    },
  ];
  return fakeFetch(routes);
}

/// The page's focus, moved by hand.
class FakeFocus implements FocusEnv {
  isFocused = true;
  silentRead = true;
  private fns = new Set<() => void>();
  focused() {
    return this.isFocused;
  }
  onFocus(fn: () => void) {
    this.fns.add(fn);
    return () => this.fns.delete(fn);
  }
  async canReadSilently() {
    return this.silentRead;
  }
  async regain() {
    this.isFocused = true;
    for (const f of this.fns) f();
    for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
  }
}

function setup(over: Partial<ServerState> = {}) {
  const fx = fixture();
  const state: ServerState = {
    access: jwt(Math.floor(NOW / 1000) + 3600),
    refresh: "refresh-1",
    twoFactor: false,
    newDevice: false,
    rememberToken: null,
    deleted: [],
    ...over,
  };
  const net = server(fx, state);
  const clip = new FakeClipboard();
  const timers = new ManualTimers();
  const device = new MapStorage();
  const focus = new FakeFocus();
  const clock = { now: NOW };
  const make = () =>
    new WebBackend({ server: SERVER, fetch: net.fetch, deviceStorage: device, clipboard: () => clip, timers, focus, idle: null, now: () => clock.now });
  return { fx, state, net, clip, timers, device, focus, clock, make, backend: make() };
}

describe("the web backend", () => {
  let t: ReturnType<typeof setup>;
  beforeEach(() => {
    t = setup();
  });

  it("introduces itself as the Rust client does", async () => {
    expect(await t.backend.login({ email: " Me@Example.com ", password: PASSWORD, server: "https://evil.example" })).toEqual({ step: "done" });
    for (const c of t.net.calls) {
      expect(c.url.startsWith(SERVER)).toBe(true);
      expect(c.headers.get("Bitwarden-Client-Name")).toBe("desktop");
      expect(c.headers.get("Bitwarden-Client-Version")).toBe("2026.6.0");
      expect(c.headers.get("Device-Type")).toBe("7");
    }
    const token = t.net.calls.find((c) => c.url.endsWith("/connect/token"))!;
    const f = Object.fromEntries(new URLSearchParams(token.body));
    expect(f).toMatchObject({ grant_type: "password", scope: "api offline_access", client_id: "cli", username: EMAIL, deviceType: "8", deviceName: "keyward", password: t.fx.m.hash });
    expect(f.deviceIdentifier).toMatch(/^[0-9a-f-]{36}$/);
    expect(token.headers.get("auth-email")).toBe(Buffer.from(EMAIL).toString("base64url"));
    expect(await t.backend.session()).toEqual({ state: "unlocked", email: EMAIL, server: SERVER, name: "Me Myself" });
    expect(t.backend.caps).toEqual({ chooseServer: false, accounts: false, biometric: false, plugins: false, clipboardClears: true });
  });

  it("builds the catalogue the desktop shows", async () => {
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    const cat = await t.backend.catalog();
    const by = (id: string) => cat.items.find((i) => i.id === id)!;

    expect(cat.items.map((i) => i.id)).not.toContain("g");
    expect(by("a")).toMatchObject({
      name: "GitLab",
      kind: "login",
      subtitle: "alex",
      folderId: "f1",
      uris: ["https://gitlab.example.com"],
      tags: { "kw-host": "git.example.com" },
      hasTotp: true,
      passkeys: 1,
      revised: "2026-09-01T10:00:00Z",
      passwordRevised: "2024-01-01T00:00:00Z",
    });
    expect(by("b")).toMatchObject({ name: "GitHub bot", orgId: "org1", collectionIds: ["c1"], subtitle: "bot" });
    expect(by("d")).toMatchObject({ kind: "card", subtitle: "Visa ·· 4242", expires: "2029-09" });
    expect(by("e")).toMatchObject({ kind: "ssh_key", subtitle: "SHA256:q3VbLx7c" });
    expect(by("f")).toMatchObject({ kind: "identity", subtitle: "alex@example.com" });
    expect(by("h").deleted).toBe(true);

    // Reuse: a and b share a password (b under its own item key and an
    // organisation's); the trashed h is not counted; c is alone.
    expect([by("a").reused, by("b").reused, by("c").reused, by("h").reused]).toEqual([1, 1, 0, 0]);
    expect(by("a").reuseGroup).not.toBeNull();
    expect(by("a").reuseGroup).toBe(by("b").reuseGroup);
    expect(by("c").reuseGroup).toBeNull();

    expect(cat.folders).toEqual([{ id: "f1", name: "Work" }]);
    expect(cat.collections).toEqual([{ id: "c1", orgId: "org1", name: "Platform", readOnly: false }]);
    expect(cat.orgs).toEqual([
      { id: "org1", name: "Acme", role: "admin", can: { editOrg: false, manageMembers: true, manageCollections: true } },
      { id: "org2", name: "Globex", role: "custom", can: { editOrg: false, manageMembers: false, manageCollections: true } },
    ]);
    // Members only where one may manage them: Acme, not Globex.
    expect(t.net.calls.some((c) => c.url.includes("organizations/org2"))).toBe(false);
    expect(cat.members).toEqual([
      { id: "m1", orgId: "org1", name: "Me Myself", email: "ME@example.com", role: "admin", status: "confirmed", twoFactor: true, accessAll: true, access: {}, isYou: true },
      { id: "m2", orgId: "org1", name: null, email: "dana@acme.example", role: "user", status: "accepted", twoFactor: false, accessAll: false, access: { c1: "read" }, isYou: false },
    ]);
  });

  it("carries no plaintext secret in the catalogue, the cards or the storage", async () => {
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    const cat = await t.backend.catalog();
    const cards = await Promise.all(cat.items.map((i) => t.backend.item(i.id)));
    const wire = JSON.stringify(cat) + JSON.stringify(cards);
    for (const s of SECRETS) expect(wire, s).not.toContain(s);
    // Stored is the device id and nothing else: no token, no key, not even
    // an encrypted one.
    expect([...t.device.m.keys()]).toEqual(["keyward.web.device"]);
    expect(t.device.dump()).toMatch(/^[0-9a-f-]{36}$/);
    const stored = t.device.dump();
    for (const s of [...SECRETS, t.fx.m.hash, b64(t.fx.user), b64(t.fx.m.stretched), t.fx.sync.profile.key, t.state.access, t.state.refresh]) {
      expect(stored, s).not.toContain(s);
    }
  });

  it("gives a card without its secrets' values", async () => {
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    const a = await t.backend.item("a");
    const f = (label: string) => a.fields.find((x) => x.label === label)!;
    expect(f("username")).toEqual({ key: "username", label: "username", value: "alex", secret: { itemId: "a", field: "username" }, mono: false });
    expect(f("password")).toMatchObject({ value: null, secret: { itemId: "a", field: "password" } });
    expect(f("totp")).toMatchObject({ value: null, secret: { itemId: "a", field: "totp" } });
    expect(f("Env")).toMatchObject({ key: null, value: "prod" });
    expect(f("Token")).toMatchObject({ value: null, secret: { itemId: "a", field: "custom", name: "Token" } });
    expect(f("Admin")).toMatchObject({ key: "checkbox", value: "true", secret: null });
    expect(f("Alias")).toMatchObject({ key: "link:100", value: null, secret: null });
    expect(a.fields.some((x) => x.label.startsWith("kw-"))).toBe(false);
    expect(a.notes).toEqual({ itemId: "a", field: "notes" });
    expect(a.passkeys).toEqual([{ rpId: "gitlab.example.com", userName: "alex" }]);
    expect(a.passwordHistory).toEqual([{ changed: "2025-06-01T00:00:00Z" }]);
    const d = await t.backend.item("d");
    expect(d.fields.find((x) => x.key === "cardNumber")).toMatchObject({ value: null, secret: { field: "cardNumber" } });
    expect(d.fields.find((x) => x.key === "expiry")).toMatchObject({ value: "09/2029" });
    expect(await code(t.backend.item("g"))).toBe("err.itemNotFound");
  });

  it("copies, and clears the clipboard after thirty seconds if it still holds the copy", async () => {
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    await t.backend.copy({ itemId: "b", field: SecretField.Password });
    expect(t.clip.text).toBe("same-secret");
    expect([...t.timers.pending.values()].map((x) => x.ms)).toEqual([30_000]);
    await t.timers.runAll();
    expect(t.clip.text).toBe("");

    // Something the person copied since is left alone.
    await t.backend.copy({ itemId: "d", field: SecretField.CardCode });
    expect(t.clip.text).toBe("cvc-987");
    t.clip.text = "the person's own text";
    await t.timers.runAll();
    expect(t.clip.text).toBe("the person's own text");

    // Reading refused: cleared regardless.
    t.clip.denyRead = true;
    await t.backend.copy({ itemId: "a", field: SecretField.Custom, name: "Token" });
    expect(t.clip.text).toBe("hidden-token-value");
    await t.timers.runAll();
    expect(t.clip.text).toBe("");

    // A TOTP field is copied as its code, never as its seed.
    await t.backend.copy({ itemId: "a", field: SecretField.Totp });
    expect(t.clip.text).toMatch(/^\d{6}$/);
  });

  it("reveals a secret for the caller to drop, and makes codes", async () => {
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    const r = await t.backend.reveal({ itemId: "e", field: SecretField.PrivateKey });
    expect(r.value).toBe("openssh-secret-material");
    r.drop();
    expect(r.value).toBe("");
    expect((await t.backend.reveal({ itemId: "a", field: SecretField.Notes })).value).toBe("note-secret");
    const code1 = await t.backend.totp("a");
    expect(code1.period).toBe(30);
    expect(code1.remaining).toBe(30 - ((NOW / 1000) % 30));
    expect(code1.code).toMatch(/^\d{6}$/);
    expect(await code(t.backend.reveal({ itemId: "g", field: SecretField.Notes }))).toBe("err.itemNotFound");
    expect(await code(t.backend.reveal({ itemId: "c", field: SecretField.Totp }))).toBe("err.secretAbsent");
  });

  it("locks and unlocks in place with the master password only; a reload is a whole login", async () => {
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    await t.backend.copy({ itemId: "a", field: SecretField.Password });
    await t.backend.lock();
    // The copy does not wait out its thirty seconds past a lock.
    expect(t.clip.text).toBe("");
    expect(await t.backend.session()).toEqual({ state: "locked", email: EMAIL, server: SERVER });
    expect(await code(t.backend.catalog())).toBe("err.locked");
    expect(await code(t.backend.reveal({ itemId: "a", field: SecretField.Password }))).toBe("err.locked");

    expect(await code(t.backend.unlock("wrong password"))).toBe("err.badPassword");
    const logins = t.net.calls.filter((c) => c.url.endsWith("/connect/token")).length;
    await t.backend.unlock(PASSWORD);
    expect(t.net.calls.filter((c) => c.url.endsWith("/connect/token")).length).toBe(logins);
    expect((await t.backend.catalog()).items.length).toBeGreaterThan(0);

    // A reload: a new backend over the same storage knows no session.
    const again = t.make();
    expect(await again.session()).toEqual({ state: "loggedOut", email: null, server: SERVER });
    expect(await code(again.unlock(PASSWORD))).toBe("err.loggedOut");

    await t.backend.logout();
    expect(await t.backend.session()).toEqual({ state: "loggedOut", email: null, server: SERVER });
    expect([...t.device.m.keys()]).toEqual(["keyward.web.device"]);
  });

  it("refuses a wrong password at login in its own words", async () => {
    expect(await code(t.backend.login({ email: EMAIL, password: "nope" }))).toBe("err.badPassword");
    expect(await t.backend.session()).toMatchObject({ state: "loggedOut" });
  });

  it("fails loudly on a forged value rather than showing less", async () => {
    const [head, ct, mac] = (t.fx.sync.ciphers[2] as { Name: string }).Name.slice(2).split("|") as [string, string, string];
    const forged = Buffer.from(ct, "base64");
    forged[0]! ^= 1;
    (t.fx.sync.ciphers[2] as { Name: string }).Name = `2.${head}|${forged.toString("base64")}|${mac}`;
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    expect(await code(t.backend.catalog())).toBe("err.macMismatch");
  });

  it("refuses a value with no mac", async () => {
    t.fx.sync.ciphers[0]!.name = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==";
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    expect(await code(t.backend.catalog())).toBe("err.encStringMalformed");
  });

  it("moves to and out of the trash, and purges only the trash", async () => {
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    await t.backend.trash(["c", "c"]);
    expect(t.state.deleted).toEqual(["PUT ciphers/c/delete "]);
    await t.backend.restore(["h"]);
    await t.backend.purge([]);
    expect(t.state.deleted).toHaveLength(2);
    expect(await code(t.backend.purge(["a"]))).toBe("err.notInTrash");
    expect(await code(t.backend.trash(["../../identity/connect/token"]))).toBe("err.badIdentifier");
    await t.backend.purge(["h", "t2"]);
    expect(t.state.deleted.at(-1)).toBe(`DELETE ciphers ${JSON.stringify({ ids: ["h", "t2"] })}`);
  });
});

describe("the login's second step", () => {
  it("asks for a second factor, refuses a wrong code, remembers on request", async () => {
    const t = setup({ twoFactor: true });
    expect(await t.backend.login({ email: EMAIL, password: PASSWORD })).toEqual({ step: "twoFactor", providers: ["authenticator", "email"] });
    expect(await code(t.backend.twoFactor({ provider: TwoFactorProvider.Authenticator, code: "000000", remember: false }))).toBe("err.badTwoFactor");
    expect(await code(t.backend.twoFactor({ provider: TwoFactorProvider.WebAuthn, code: "x", remember: false }))).toBe("err.twoFactorUnsupported");
    expect(await t.backend.twoFactor({ provider: TwoFactorProvider.Authenticator, code: "123 456", remember: true })).toEqual({ step: "done" });
    // The remember token is a credential: in memory, never in storage.
    expect(t.device.dump()).not.toContain("remember-me-token");
    expect(await t.backend.session()).toMatchObject({ state: "unlocked" });

    // Logging in again in this tab: the remember token stands in for the code.
    await t.backend.lock();
    expect(await t.backend.login({ email: EMAIL, password: PASSWORD })).toEqual({ step: "done" });
    const last = t.net.calls.filter((c) => c.url.endsWith("/connect/token")).at(-1)!;
    expect(Object.fromEntries(new URLSearchParams(last.body))).toMatchObject({ twoFactorProvider: "5", twoFactorToken: "remember-me-token" });
  });

  it("asks for the new device's code and sends it as newDeviceOtp", async () => {
    const t = setup({ newDevice: true });
    expect(await t.backend.login({ email: EMAIL, password: PASSWORD })).toEqual({ step: "newDevice" });
    expect(await code(t.backend.twoFactor({ provider: TwoFactorProvider.Email, code: "222222", remember: false }))).toBe("err.badNewDeviceCode");
    expect(await t.backend.twoFactor({ provider: TwoFactorProvider.Email, code: "111111", remember: false })).toEqual({ step: "done" });
    const last = t.net.calls.filter((c) => c.url.endsWith("/connect/token")).at(-1)!;
    const f = Object.fromEntries(new URLSearchParams(last.body));
    expect(f.newDeviceOtp).toBe("111111");
    expect(f.twoFactorToken).toBeUndefined();
  });

  it("drops a login in progress on lock", async () => {
    const t = setup({ twoFactor: true });
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    await t.backend.lock();
    expect(await code(t.backend.twoFactor({ provider: TwoFactorProvider.Authenticator, code: "123456", remember: false }))).toBe("err.noPendingLogin");
  });
});

describe("tokens", () => {
  it("refreshes a spent access token and keeps the rotated refresh token", async () => {
    const t = setup();
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    // The token runs out by its own exp.
    t.clock.now = NOW + 3600_000;
    await t.backend.sync();
    const refreshes = () =>
      t.net.calls.filter((c) => c.url.endsWith("/connect/token")).map((c) => Object.fromEntries(new URLSearchParams(c.body))).filter((f) => f.grant_type === "refresh_token");
    expect(refreshes().map((f) => f.refresh_token)).toEqual(["refresh-1"]);
    expect(t.net.calls.at(-1)!.headers.get("Authorization")).toBe(`Bearer ${t.state.access}`);
    // The next refresh sends the rotated refresh token.
    t.clock.now = NOW + 11 * 86400_000;
    await t.backend.sync();
    expect(refreshes().map((f) => f.refresh_token).slice(0, 2)).toEqual(["refresh-1", "refresh-1+"]);
  });

  it("answers a 401 with one refresh and one retry", async () => {
    const t = setup();
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    t.state.access = jwt(Math.floor(NOW / 1000) + 3600, "revoked-elsewhere");
    await t.backend.sync();
    const grants = t.net.calls.filter((c) => c.url.endsWith("/connect/token")).map((c) => new URLSearchParams(c.body).get("grant_type"));
    expect(grants).toEqual(["password", "refresh_token"]);
  });

  it("signs out when the server has ended the session", async () => {
    const t = setup();
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    t.state.access = "rotated-away";
    t.state.refresh = "someone-else";
    expect(await code(t.backend.sync())).toBe("err.sessionEnded");
    expect(await t.backend.session()).toMatchObject({ state: "loggedOut" });
  });
});

describe("the idle lock", () => {
  function idleEnv() {
    const timers = new ManualTimers();
    let activity: (() => void) | null = null;
    let visibility: ((hidden: boolean) => void) | null = null;
    let now = 0;
    const env: IdleEnv = {
      now: () => now,
      setTimeout: (fn, ms) => timers.setTimeout(fn, ms),
      clearTimeout: (h) => timers.clearTimeout(h),
      onActivity: (fn) => ((activity = fn), () => (activity = null)),
      onVisibility: (fn) => ((visibility = fn), () => (visibility = null)),
    };
    return { env, timers, act: () => activity?.(), show: (h: boolean) => visibility?.(h), advance: (ms: number) => (now += ms) };
  }

  it("locks after the timeout, and on coming back after a long absence", async () => {
    const fx = fixture();
    const state: ServerState = { access: jwt(Math.floor(NOW / 1000) + 3600), refresh: "r", twoFactor: false, newDevice: false, rememberToken: null, deleted: [] };
    const net = server(fx, state);
    const idle = idleEnv();
    const b = new WebBackend({ server: SERVER, fetch: net.fetch, deviceStorage: new MapStorage(), clipboard: () => new FakeClipboard(), timers: new ManualTimers(), focus: null, idle: idle.env, idleTimeoutMs: 1000, now: () => NOW });
    await b.login({ email: EMAIL, password: PASSWORD });
    expect([...idle.timers.pending.values()].map((x) => x.ms)).toEqual([1000]);
    await idle.timers.runAll();
    expect(await b.session()).toMatchObject({ state: "locked" });

    await b.unlock(PASSWORD);
    idle.show(true);
    idle.advance(1001);
    idle.show(false);
    for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
    expect(await b.session()).toMatchObject({ state: "locked" });
  });
});

describe("the KDF's bounds", () => {
  it("refuses a prelogin outside them before the password is touched", async () => {
    for (const body of [
      { kdf: 0, kdfIterations: 1 },
      { kdf: 0, kdfIterations: 99_999 },
      { kdf: 0, kdfIterations: 2_000_001 },
      { kdf: 1, kdfIterations: 1, kdfMemory: 64, kdfParallelism: 4 },
      { kdf: 1, kdfIterations: 3, kdfMemory: 15, kdfParallelism: 4 },
      { kdf: 1, kdfIterations: 3, kdfMemory: 4096, kdfParallelism: 4 },
      { kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 17 },
    ]) {
      const t = setup();
      const net = fakeFetch([(r) => (r.url.endsWith("/accounts/prelogin") ? { status: 200, body } : undefined)]);
      const b = new WebBackend({ server: SERVER, fetch: net.fetch, deviceStorage: new MapStorage(), clipboard: () => t.clip, timers: t.timers, focus: null, idle: null });
      expect(await code(b.login({ email: EMAIL, password: PASSWORD })), JSON.stringify(body)).toBe("err.kdfOutOfRange");
      // Nothing derived, nothing sent: the prelogin was the only request.
      expect(net.calls.map((c) => c.url)).toEqual([`${SERVER}/identity/accounts/prelogin`]);
    }
  });
});

describe("the clipboard's clear", () => {
  it("waits for the focus when it cannot clear, says so, and clears on the focus's return", async () => {
    const t = setup();
    const states: string[] = [];
    t.backend.watchClipboard((s) => states.push(s));
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    await t.backend.copy({ itemId: "c", field: SecretField.Password });
    expect(t.backend.clipboardState()).toBe("waiting");
    t.focus.isFocused = false;
    await t.timers.runAll();
    // Due, not done: the secret is still there, and the state says it.
    expect(t.clip.text).toBe("own-secret");
    expect(t.backend.clipboardState()).toBe("stuck");
    await t.focus.regain();
    expect(t.clip.text).toBe("");
    expect(t.backend.clipboardState()).toBe("idle");
    expect(states).toEqual(["waiting", "stuck", "idle"]);
  });

  it("keeps a refused write pending and retries it", async () => {
    const t = setup();
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    await t.backend.copy({ itemId: "c", field: SecretField.Password });
    const write = t.clip.writeText.bind(t.clip);
    let refuse = true;
    t.clip.writeText = async (s: string) => {
      if (refuse) throw new Error("NotAllowedError");
      await write(s);
    };
    await t.timers.runAll();
    expect(t.clip.text).toBe("own-secret");
    expect(t.backend.clipboardState()).toBe("stuck");
    refuse = false;
    await t.focus.regain();
    expect(t.clip.text).toBe("");
    expect(t.backend.clipboardState()).toBe("idle");
  });

  it("never reads where a read would prompt: it overwrites instead", async () => {
    const t = setup();
    t.focus.silentRead = false;
    let reads = 0;
    const read = t.clip.readText.bind(t.clip);
    t.clip.readText = async () => {
      reads++;
      return read();
    };
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    await t.backend.copy({ itemId: "c", field: SecretField.Password });
    t.clip.text = "the person's own text";
    await t.timers.runAll();
    expect(reads).toBe(0);
    expect(t.clip.text).toBe("");
  });

  it("a lock while unfocused leaves the clear pending until the focus returns", async () => {
    const t = setup();
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    await t.backend.copy({ itemId: "c", field: SecretField.Password });
    t.focus.isFocused = false;
    await t.backend.lock();
    expect(t.clip.text).toBe("own-secret");
    expect(t.backend.clipboardState()).toBe("stuck");
    await t.focus.regain();
    expect(t.clip.text).toBe("");
  });

  it("says it cannot clear where there is no clipboard", async () => {
    const t = setup();
    const b = new WebBackend({ server: SERVER, fetch: t.net.fetch, deviceStorage: new MapStorage(), clipboard: () => undefined, timers: t.timers, focus: null, idle: null });
    expect(b.caps.clipboardClears).toBe(false);
    expect(t.backend.caps.clipboardClears).toBe(true);
  });
});

describe("the re-prompt", () => {
  it("opens nothing of a reprompt item without a fresh master password", async () => {
    const t = setup();
    (t.fx.sync.ciphers[0] as { reprompt?: number }).reprompt = 1;
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    const a: SecretRef = { itemId: "a", field: SecretField.Password };
    expect(await code(t.backend.reveal(a))).toBe("err.repromptRequired");
    expect(await code(t.backend.copy(a))).toBe("err.repromptRequired");
    expect(await code(t.backend.copy({ itemId: "a", field: SecretField.Totp }))).toBe("err.repromptRequired");
    expect(await code(t.backend.totp("a"))).toBe("err.repromptRequired");
    expect(t.clip.text).toBe("");
    // The card itself still shows: only secrets are gated.
    expect((await t.backend.item("a")).fields.find((f) => f.key === "username")?.value).toBe("alex");
    // Other items are not.
    expect((await t.backend.reveal({ itemId: "c", field: SecretField.Password })).value).toBe("own-secret");

    expect(await code(t.backend.verifyReprompt("a", "wrong"))).toBe("err.badPassword");
    expect(await code(t.backend.reveal(a))).toBe("err.repromptRequired");
    expect(await code(t.backend.verifyReprompt("g", PASSWORD))).toBe("err.itemNotFound");

    await t.backend.verifyReprompt("a", PASSWORD);
    expect((await t.backend.reveal(a)).value).toBe("same-secret");
    expect((await t.backend.totp("a")).code).toMatch(/^\d{6}$/);
    // A minute later it asks again.
    t.clock.now += 60_001;
    expect(await code(t.backend.reveal(a))).toBe("err.repromptRequired");

    // A lock forgets the re-prompts seen.
    await t.backend.verifyReprompt("a", PASSWORD);
    await t.backend.lock();
    await t.backend.unlock(PASSWORD);
    expect(await code(t.backend.reveal(a))).toBe("err.repromptRequired");
  });

  it("checks the password against the key the session opened, not one the server swaps in", async () => {
    const t = setup();
    (t.fx.sync.ciphers[0] as { reprompt?: number }).reprompt = 1;
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    const evil = masterOf("server's choice", EMAIL, ITER);
    t.fx.sync.profile.key = enc2(evil.stretched, t.fx.user);
    await t.backend.sync();
    expect(await code(t.backend.verifyReprompt("a", "server's choice"))).toBe("err.badPassword");
    await t.backend.verifyReprompt("a", PASSWORD);
    expect((await t.backend.reveal({ itemId: "a", field: SecretField.Password })).value).toBe("same-secret");
  });
});

describe("a login waiting for its second step", () => {
  it("is dropped after five minutes", async () => {
    const t = setup({ twoFactor: true });
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    expect(await t.backend.session()).toMatchObject({ state: "loggedOut", email: EMAIL });
    t.clock.now += 5 * 60_000 + 1;
    expect(await code(t.backend.twoFactor({ provider: TwoFactorProvider.Authenticator, code: "123456", remember: false }))).toBe("err.noPendingLogin");
    expect(await t.backend.session()).toMatchObject({ state: "loggedOut", email: null });
  });

  it("is dropped by its timer, and the window is told", async () => {
    const t = setup({ twoFactor: true });
    const changes: string[] = [];
    t.backend.subscribe((c) => changes.push(c.kind));
    await t.backend.login({ email: EMAIL, password: PASSWORD });
    expect([...t.timers.pending.values()].map((x) => x.ms)).toEqual([5 * 60_000 + 1]);
    await t.timers.runAll();
    expect(changes.at(-1)).toBe("session");
    expect(await code(t.backend.sendTwoFactorCode(TwoFactorProvider.Email))).toBe("err.noPendingLogin");
  });
});
