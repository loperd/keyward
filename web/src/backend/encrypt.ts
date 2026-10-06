// New ciphertext, in the only forms the reading side accepts (encstring.ts):
//   2.iv|ct|mac  AES-256-CBC under a fresh random IV, then HMAC-SHA256 over
//                `iv || ct` — every value an item, a folder or a collection
//                carries;
//   4.ct         RSA-OAEP with SHA-1 — an organisation key handed to a member
//                on confirm, the form the official clients write it in.
// The keys are the KeyRing's non-extractable CryptoKeys; nothing here ever
// holds a key's bytes except an organisation key in the one moment it is
// sealed for a member, and those bytes are the caller's to wipe.
//
// A secret enters as bytes and the bytes are wiped once sealed. A JavaScript
// string cannot be wiped, so `encryptText` turns one into bytes at the last
// moment and wipes them; the string is the caller's to let go of.
import { concat, fromB64, toB64, utf8, zero, type Bytes } from "./bytes";
import { randomBytes, type SymKey } from "./crypto";
import { fail } from "./errors";

const subtle = () => globalThis.crypto.subtle;

/// A member's public key is RSA-2048, exactly: Bitwarden makes no other, a
/// shorter one is not to be sealed for, and a longer one seals into a `4.`
/// whose ciphertext is not the 256 bytes every reader of the format expects.
export const RSA_BITS = 2048;

/// Bytes into `2.iv|ct|mac`. The plaintext is the caller's to wipe (the text
/// form below does it); the ciphertext and mac are public.
export async function encryptBytes(key: SymKey, plain: Bytes): Promise<string> {
  const iv = randomBytes(16);
  let ct: Bytes;
  try {
    ct = new Uint8Array(await subtle().encrypt({ name: "AES-CBC", iv }, key.enc, plain));
  } catch {
    return fail("err.encryptFailed", { reason: "aes" });
  }
  let mac: Bytes;
  try {
    mac = new Uint8Array(await subtle().sign("HMAC", key.mac, concat(iv, ct)));
  } catch {
    return fail("err.encryptFailed", { reason: "hmac" });
  }
  if (mac.length !== 32 || ct.length === 0 || ct.length % 16 !== 0) fail("err.encryptFailed", { reason: "shape" });
  return `2.${toB64(iv)}|${toB64(ct)}|${toB64(mac)}`;
}

/// Text into `2.iv|ct|mac`: encoded to bytes here, sealed, the bytes wiped.
export async function encryptText(key: SymKey, text: string): Promise<string> {
  const bytes = utf8(text);
  try {
    return await encryptBytes(key, bytes);
  } finally {
    zero(bytes);
  }
}

/// A member's public key as the server gives it: base64 of the SPKI DER.
/// Imported for RSA-OAEP with SHA-1 — the hash the confirm's `4.` form says —
/// and refused when it is not RSA-2048 (`RSA_BITS`).
export async function importMemberPublicKey(spkiB64: string): Promise<CryptoKey> {
  let der: Bytes;
  try {
    der = fromB64(spkiB64);
  } catch {
    return fail("err.memberKeyMalformed", { reason: "base64" });
  }
  let key: CryptoKey;
  try {
    key = await subtle().importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-1" }, false, ["encrypt"]);
  } catch {
    return fail("err.memberKeyMalformed", { reason: "spki" });
  }
  const alg = key.algorithm as RsaHashedKeyAlgorithm;
  if (alg.name !== "RSA-OAEP" || typeof alg.modulusLength !== "number") fail("err.memberKeyMalformed", { reason: "algorithm" });
  if (alg.modulusLength < RSA_BITS) fail("err.memberKeyWeak", { bits: alg.modulusLength, min: RSA_BITS });
  if (alg.modulusLength !== RSA_BITS) fail("err.memberKeyMalformed", { reason: "size" });
  return key;
}

/// Raw key bytes sealed for a member as `4.ct`. The bytes are the caller's
/// to wipe, right after.
export async function sealForMember(publicKey: CryptoKey, raw: Bytes): Promise<string> {
  try {
    return `4.${toB64(new Uint8Array(await subtle().encrypt({ name: "RSA-OAEP" }, publicKey, raw)))}`;
  } catch {
    return fail("err.encryptFailed", { reason: "rsa" });
  }
}
