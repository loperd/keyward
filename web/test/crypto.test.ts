import { describe, expect, it } from "vitest";
import { fromB64, toB64 } from "../src/backend/bytes";
import { importSymKey, stretch } from "../src/backend/crypto";
import { decryptString, parseEncString } from "../src/backend/encstring";
import { isWebError } from "../src/backend/errors";
import { deriveMasterKey, fromPassword, masterPasswordHash, KdfKind } from "../src/backend/kdf";
import { KeyRing } from "../src/backend/keys";
import { b64, enc2, encRsa, masterOf, rsaPair } from "./helpers";
import * as nc from "node:crypto";

const code = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    if (isWebError(e)) return e.code;
    throw e;
  }
  return "no error";
};

describe("the KDF", () => {
  // The same vector as crates/bw/src/crypto.rs: computed by hashlib, an
  // implementation of PBKDF2 other than ours.
  it("derives PBKDF2's master key and hash as the Rust client does", async () => {
    const mk = await deriveMasterKey("password", "nobody@example.com", { kind: KdfKind.Pbkdf2, iterations: 100_000 });
    expect(toB64(mk)).toBe("QVBMpLXA72bJyjN3kbRvA0ipNCz9FkPjA2jmqUUzA8Q=");
    expect(await masterPasswordHash(mk, "password")).toBe("9l0bhF2MScUS3qI2Ty/FbiQWgf7rU9s9TyO1BdX6TVc=");
  });

  // Computed with Node's OpenSSL Argon2id (crypto.argon2Sync), not hash-wasm:
  // salt = SHA-256(email), m = 64 MiB, t = 3, p = 4.
  it("derives Argon2id's master key and hash", async () => {
    const kdf = { kind: KdfKind.Argon2id, iterations: 3, memoryMiB: 64, parallelism: 4 } as const;
    const mk = await deriveMasterKey("password", "Nobody@Example.com ", kdf);
    expect(toB64(mk)).toBe("jJdgvHtolAVb7rSmHi3S2VDXilmhAcvmCk13kixFjww=");
    expect(await masterPasswordHash(mk, "password")).toBe("wA3GkGqDj5uBTvy52tEGyGRK2p78L2WYqp0nVsm+9YY=");
  });

  it("stretches the master key by HKDF-Expand (enc, mac)", async () => {
    // Expected halves computed by Python's hmac: HMAC(mk, "enc\x01").
    const enc = fromB64("cxXjuSHNSWjqtN7J/aWApXYA9XtetJBfTQCPuaftSzc=");
    const mac = fromB64("4BY7PJAwWnZ+HEH1MXJRu4PnMXjQwku9x2sqfV/VzhA=");
    const raw = new Uint8Array([...enc, ...mac]);
    const sealed = enc2(raw, "opened by the stretched key");
    const key = await stretch(fromB64("QVBMpLXA72bJyjN3kbRvA0ipNCz9FkPjA2jmqUUzA8Q="));
    expect(await decryptString(sealed, key)).toBe("opened by the stretched key");
    // The stretched halves cannot be read back out.
    expect(key.enc.extractable).toBe(false);
    expect(key.mac.extractable).toBe(false);
  });

  it("agrees with an independent computation of the whole chain", async () => {
    const m = masterOf("correct horse", "A@B.example", 100_000);
    const { hash, stretched } = await fromPassword("correct horse", "a@b.example", { kind: KdfKind.Pbkdf2, iterations: 100_000 });
    expect(hash).toBe(m.hash);
    expect(await decryptString(enc2(m.stretched, "x"), stretched)).toBe("x");
  });
});

describe("EncString type 2", () => {
  const raw = () => new Uint8Array(nc.randomBytes(64));

  it("round-trips text, and the key's bytes are wiped on import", async () => {
    const r = raw();
    const keep = r.slice();
    const key = await importSymKey(r);
    expect(r.every((b) => b === 0)).toBe(true);
    for (const text of ["", "secret", "пароль 🔑", "x".repeat(1000)]) {
      expect(await decryptString(enc2(keep, text), key)).toBe(text);
    }
  });

  it("refuses a tampered ciphertext, iv or mac by the mac, before decrypting", async () => {
    const r = raw();
    const sealed = enc2(r, "secret");
    const key = await importSymKey(r.slice());
    const [head, ct, mac] = sealed.slice(2).split("|") as [string, string, string];
    const flip = (s: string) => {
      const b = fromB64(s);
      b[0]! ^= 1;
      return toB64(b);
    };
    for (const bad of [`2.${flip(head)}|${ct}|${mac}`, `2.${head}|${flip(ct)}|${mac}`, `2.${head}|${ct}|${flip(mac)}`]) {
      expect(await code(decryptString(bad, key))).toBe("err.macMismatch");
    }
  });

  it("refuses a wrong key by the mac, not by rubbish", async () => {
    const sealed = enc2(raw(), "secret");
    expect(await code(decryptString(sealed, await importSymKey(raw())))).toBe("err.macMismatch");
  });

  it("refuses every other shape outright", async () => {
    const key = await importSymKey(raw());
    // Type 0 has no mac: reading it would be a padding oracle.
    expect(await code(decryptString("0.aXY=|Y3Q=", key))).toBe("err.encTypeUnsupported");
    expect(await code(decryptString("1.aXY=|Y3Q=|bWFj", key))).toBe("err.encTypeUnsupported");
    for (const bad of ["", "hello", "2.only-one-part", "2.aXY=|Y3Q=", "2.a|b|c|d", "2.!!!|Y3Q=|bWFj"]) {
      expect(await code(decryptString(bad, key)), bad).toMatch(/^err\.(encStringMalformed|encTypeUnsupported)$/);
    }
    expect(() => parseEncString("9.abc")).toThrow();
  });

  it("refuses a key that is not 64 bytes", async () => {
    expect(await code(importSymKey(new Uint8Array(32)))).toBe("err.keyMalformed");
  });
});

describe("organisation keys", () => {
  it("reads Bitwarden's RSA types by their numbers: 3 is SHA-256, 4 is SHA-1, 5 and 6 are refused", async () => {
    const user = new Uint8Array(nc.randomBytes(64));
    const pair = rsaPair();
    const org = new Uint8Array(nc.randomBytes(64));
    const m = masterOf("pw", "me@example.com", 1000);
    const ring = await KeyRing.open(enc2(m.stretched, user), await stretch(m.mk));
    await ring.load(enc2(user, pair.der), []);
    const sha256ct = nc.publicEncrypt({ key: pair.publicKey, padding: nc.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, org);
    const sha1ct = nc.publicEncrypt({ key: pair.publicKey, padding: nc.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, org);
    expect(parseEncString(`3.${b64(sha256ct)}`).type).toBe(3);
    expect(parseEncString(`4.${b64(sha1ct)}`).type).toBe(4);
    // Each number opens only with its own hash: a SHA-256 ciphertext labelled
    // 4 does not decrypt.
    await ring.load(enc2(user, pair.der), [{ id: "x", key: `3.${b64(sha256ct)}` }]);
    await ring.load(enc2(user, pair.der), [{ id: "y", key: `4.${b64(sha1ct)}` }]);
    expect(await code(ring.load(enc2(user, pair.der), [{ id: "z", key: `4.${b64(sha256ct)}` }]))).toBe("err.decryptFailed");
    // The HMAC'd RSA types are retired and refused by name, mac or not.
    const mac = b64(nc.randomBytes(32));
    for (const t of ["5", "6"]) {
      expect(await code(ring.load(enc2(user, pair.der), [{ id: "w", key: `${t}.${b64(sha1ct)}|${mac}` }])), t).toBe("err.encTypeUnsupported");
      expect(() => parseEncString(`${t}.${b64(sha1ct)}`)).toThrow("err.encTypeUnsupported");
    }
    // An RSA value that is not 2048 bits long is not Rsa2048_*.
    expect(() => parseEncString(`4.${b64(nc.randomBytes(128))}`)).toThrow("err.encStringMalformed");
  });

  it("unwraps an RSA-OAEP (SHA-1, type 4) and a SHA-256 (type 3) org key", async () => {
    const user = new Uint8Array(nc.randomBytes(64));
    const pair = rsaPair();
    const orgA = new Uint8Array(nc.randomBytes(64));
    const orgB = new Uint8Array(nc.randomBytes(64));
    const m = masterOf("pw", "me@example.com", 1000);
    const ring = await KeyRing.open(enc2(m.stretched, user), await stretch(m.mk));
    await ring.load(enc2(user, pair.der), [
      { id: "a", key: encRsa(pair.publicKey, orgA) },
      { id: "b", key: encRsa(pair.publicKey, orgB, true) },
      { id: "pending", key: null },
    ]);
    expect(await decryptString(enc2(orgA, "from a"), ring.base("a"))).toBe("from a");
    expect(await decryptString(enc2(orgB, "from b"), ring.base("b"))).toBe("from b");
    expect(() => ring.base("pending")).toThrow("err.noOrgKey");
    // A key of one organisation does not open another's values.
    expect(await code(decryptString(enc2(orgA, "x"), ring.base("b")))).toBe("err.macMismatch");
    ring.drop();
    expect(() => ring.base(null)).toThrow("err.locked");
  });

  it("says a wrong master password as such", async () => {
    const m = masterOf("right", "me@example.com", 1000);
    const wrong = masterOf("wrong", "me@example.com", 1000);
    const sealed = enc2(m.stretched, new Uint8Array(64));
    expect(await code(KeyRing.open(sealed, await stretch(wrong.mk)))).toBe("err.badPassword");
    expect(b64(m.stretched)).not.toBe(b64(wrong.stretched));
  });
});

describe("the KDF's bounds", () => {
  it("accepts the edges and refuses one step past them", async () => {
    const { checkKdf } = await import("../src/backend/kdf");
    const { readPrelogin } = await import("../src/backend/api");
    const ok = [
      { kind: KdfKind.Pbkdf2, iterations: 100_000 },
      { kind: KdfKind.Pbkdf2, iterations: 2_000_000 },
      { kind: KdfKind.Argon2id, iterations: 2, memoryMiB: 16, parallelism: 1 },
      { kind: KdfKind.Argon2id, iterations: 10, memoryMiB: 1024, parallelism: 16 },
    ] as const;
    for (const k of ok) expect(checkKdf(k)).toBe(k);
    const bad = [
      { kind: KdfKind.Pbkdf2, iterations: 99_999 },
      { kind: KdfKind.Pbkdf2, iterations: 2_000_001 },
      { kind: KdfKind.Pbkdf2, iterations: 100_000.5 },
      { kind: KdfKind.Argon2id, iterations: 1, memoryMiB: 64, parallelism: 4 },
      { kind: KdfKind.Argon2id, iterations: 11, memoryMiB: 64, parallelism: 4 },
      { kind: KdfKind.Argon2id, iterations: 3, memoryMiB: 15, parallelism: 4 },
      { kind: KdfKind.Argon2id, iterations: 3, memoryMiB: 1025, parallelism: 4 },
      { kind: KdfKind.Argon2id, iterations: 3, memoryMiB: 64, parallelism: 0 },
      { kind: KdfKind.Argon2id, iterations: 3, memoryMiB: 64, parallelism: 17 },
    ] as const;
    for (const k of bad) {
      expect(() => checkKdf(k), JSON.stringify(k)).toThrow("err.kdfOutOfRange");
      // And no derivation runs on them, whoever calls.
      expect(await code(deriveMasterKey("pw", "a@b.example", k)), JSON.stringify(k)).toBe("err.kdfOutOfRange");
    }
    expect(() => readPrelogin(200, JSON.stringify({ kdf: 0, kdfIterations: 5000 }))).toThrow("err.kdfOutOfRange");
    expect(() => readPrelogin(200, JSON.stringify({ Kdf: 1, KdfIterations: 3, KdfMemory: 2048, KdfParallelism: 4 }))).toThrow("err.kdfOutOfRange");
    expect(readPrelogin(200, JSON.stringify({ kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 }))).toEqual({ kind: KdfKind.Argon2id, iterations: 3, memoryMiB: 64, parallelism: 4 });
  });
});
