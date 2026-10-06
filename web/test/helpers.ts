// The tests' own Bitwarden: keys and ciphertexts made with node:crypto, an
// implementation independent of the backend's WebCrypto code, so a mistake in
// one cannot agree with itself in the other.
import * as nc from "node:crypto";
import type { StorageLike } from "../src/backend/session";

export const b64 = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64");

/// `2.iv|ct|mac` under a 64-byte key (32 enc, 32 mac).
export function enc2(key: Uint8Array, plain: string | Uint8Array): string {
  const iv = nc.randomBytes(16);
  const c = nc.createCipheriv("aes-256-cbc", key.subarray(0, 32), iv);
  const ct = Buffer.concat([c.update(typeof plain === "string" ? Buffer.from(plain, "utf8") : plain), c.final()]);
  const mac = nc.createHmac("sha256", key.subarray(32, 64)).update(Buffer.concat([iv, ct])).digest();
  return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}

/// The master key, password hash and stretched pair, computed the way
/// Bitwarden documents them, with node's own PBKDF2 and HMAC.
export function masterOf(password: string, email: string, iterations: number) {
  const mk = nc.pbkdf2Sync(password, email.trim().toLowerCase(), iterations, 32, "sha256");
  const hash = b64(nc.pbkdf2Sync(mk, password, 1, 32, "sha256"));
  const stretched = Buffer.concat([
    nc.createHmac("sha256", mk).update(Buffer.from("enc\x01")).digest(),
    nc.createHmac("sha256", mk).update(Buffer.from("mac\x01")).digest(),
  ]);
  return { mk, hash, stretched };
}

export function rsaPair() {
  const { publicKey, privateKey } = nc.generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    publicKey,
    der: privateKey.export({ type: "pkcs8", format: "der" }),
  };
}

/// `4.ct` (SHA-1) or `3.ct` (SHA-256) for an organisation key.
export function encRsa(publicKey: nc.KeyObject, data: Uint8Array, sha256 = false): string {
  const ct = nc.publicEncrypt({ key: publicKey, padding: nc.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: sha256 ? "sha256" : "sha1" }, data);
  return `${sha256 ? 3 : 4}.${b64(ct)}`;
}

export class MapStorage implements StorageLike {
  readonly m = new Map<string, string>();
  getItem(k: string) {
    return this.m.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.m.set(k, v);
  }
  removeItem(k: string) {
    this.m.delete(k);
  }
  dump() {
    return [...this.m.values()].join("\n");
  }
}

/// A JWT with only an `exp`, as the server's tokens carry.
export function jwt(exp: number, tag = "a"): string {
  const e = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${e({ alg: "RS256" })}.${e({ exp, tag })}.sig`;
}

export type Route = (req: { url: string; method: string; headers: Headers; body: string }) => { status: number; body: unknown } | undefined;

/// A fake fetch: each request goes to the first route that answers it, and is
/// recorded.
export function fakeFetch(routes: Route[]) {
  const calls: { url: string; method: string; headers: Headers; body: string }[] = [];
  const fetch = async (url: string, init: RequestInit) => {
    const req = { url, method: init.method ?? "GET", headers: new Headers(init.headers), body: typeof init.body === "string" ? init.body : "" };
    calls.push(req);
    for (const r of routes) {
      const a = r(req);
      if (a) return new Response(typeof a.body === "string" ? a.body : JSON.stringify(a.body), { status: a.status });
    }
    return new Response("no route", { status: 599 });
  };
  return { fetch, calls };
}

export class FakeClipboard {
  text = "";
  denyRead = false;
  async writeText(t: string) {
    this.text = t;
  }
  async readText() {
    if (this.denyRead) throw new Error("denied");
    return this.text;
  }
}

/// Timers run by hand.
export class ManualTimers {
  private next = 1;
  readonly pending = new Map<number, { fn: () => void; ms: number }>();
  setTimeout(fn: () => void, ms: number) {
    const id = this.next++;
    this.pending.set(id, { fn, ms });
    return id;
  }
  clearTimeout(h: unknown) {
    this.pending.delete(h as number);
  }
  async runAll() {
    const all = [...this.pending.entries()];
    this.pending.clear();
    for (const [, t] of all) t.fn();
    // Let the cleared callbacks' promises settle.
    for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
  }
}
