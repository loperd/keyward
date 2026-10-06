// The keys, as WebCrypto holds them. Every key is imported NON-EXTRACTABLE
// the moment its bytes exist, and the bytes are wiped right after: from then
// on the tab can use a key but no script — ours or one that got in — can read
// it back out. Writing new ciphertext lives in encrypt.ts, with these keys.
import { zero, type Bytes } from "./bytes";
import { fail } from "./errors";

const subtle = () => globalThis.crypto.subtle;

/// A pair: AES-256-CBC to decrypt and encrypt, HMAC-SHA256 to check the mac
/// first and to sign a new value's.
export type SymKey = { readonly enc: CryptoKey; readonly mac: CryptoKey };

/// The user's RSA private key, imported once per hash: WebCrypto binds the
/// OAEP hash to the key, and Bitwarden uses SHA-1 (type 4) and SHA-256
/// (type 3).
export type PrivateKey = { readonly sha1: CryptoKey; readonly sha256: CryptoKey };

/// 64 bytes — 32 encrypt, 32 sign — into a key pair. The bytes are wiped
/// here whether the import works or not: the caller never keeps them.
export async function importSymKey(raw: Bytes): Promise<SymKey> {
  try {
    if (raw.length !== 64) fail("err.keyMalformed", { reason: "length", length: raw.length });
    const encBytes = raw.slice(0, 32);
    const macBytes = raw.slice(32, 64);
    try {
      const enc = await subtle().importKey("raw", encBytes, { name: "AES-CBC" }, false, ["decrypt", "encrypt"]);
      const mac = await subtle().importKey("raw", macBytes, { name: "HMAC", hash: "SHA-256" }, false, ["verify", "sign"]);
      return { enc, mac };
    } finally {
      zero(encBytes, macBytes);
    }
  } finally {
    zero(raw);
  }
}

/// The master key stretched into the pair that opens the protected user key:
/// HKDF-Expand(masterKey, "enc"/"mac", 32). For one block of output Expand is
/// a single HMAC over `info || 0x01`; WebCrypto's HKDF always runs Extract
/// first, which is not what Bitwarden does, so the block is computed directly.
/// The master key's bytes are the caller's to wipe.
export async function stretch(masterKey: Bytes): Promise<SymKey> {
  const prk = await subtle().importKey("raw", masterKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const block = async (info: string) =>
    new Uint8Array(await subtle().sign("HMAC", prk, new Uint8Array([...info].map((c) => c.charCodeAt(0)).concat(1))));
  const raw = new Uint8Array(64);
  const enc = await block("enc");
  const mac = await block("mac");
  raw.set(enc, 0);
  raw.set(mac, 32);
  zero(enc, mac);
  return importSymKey(raw);
}

/// AES-256-CBC after the mac was checked in constant time. The mac covers
/// `iv || ct`; WebCrypto's `verify` compares without an early exit, and the
/// expected mac never leaves it. A mismatch is a wrong key or a forgery — the
/// ciphertext is not touched.
export async function decryptSym(key: SymKey, iv: Bytes, ct: Bytes, mac: Bytes): Promise<Bytes> {
  const data = new Uint8Array(iv.length + ct.length);
  data.set(iv, 0);
  data.set(ct, iv.length);
  const ok = await subtle().verify("HMAC", key.mac, mac, data);
  if (!ok) fail("err.macMismatch");
  try {
    return new Uint8Array(await subtle().decrypt({ name: "AES-CBC", iv }, key.enc, ct));
  } catch {
    // The mac held, so the key is right and the padding is not: the value
    // was written wrong. Said as such, never as a value.
    return fail("err.decryptFailed", { reason: "padding" });
  }
}

/// The user's private key from its PKCS#8 DER. The DER is the caller's to
/// wipe, right after.
export async function importPrivateKey(der: Bytes): Promise<PrivateKey> {
  try {
    const sha1 = await subtle().importKey("pkcs8", der, { name: "RSA-OAEP", hash: "SHA-1" }, false, ["decrypt"]);
    const sha256 = await subtle().importKey("pkcs8", der, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
    return { sha1, sha256 };
  } catch {
    return fail("err.keyMalformed", { reason: "pkcs8" });
  }
}

export async function decryptRsa(key: PrivateKey, sha256: boolean, ct: Bytes): Promise<Bytes> {
  try {
    return new Uint8Array(await subtle().decrypt({ name: "RSA-OAEP" }, sha256 ? key.sha256 : key.sha1, ct));
  } catch {
    return fail("err.decryptFailed", { reason: "rsa" });
  }
}

export async function sha256(...parts: Bytes[]): Promise<Bytes> {
  const n = parts.reduce((s, p) => s + p.length, 0);
  const all = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    all.set(p, at);
    at += p.length;
  }
  try {
    return new Uint8Array(await subtle().digest("SHA-256", all));
  } finally {
    // The parts may hold a password (reuse detection hashes one).
    zero(all);
  }
}

export const randomBytes = (n: number): Bytes => globalThis.crypto.getRandomValues(new Uint8Array(n));
