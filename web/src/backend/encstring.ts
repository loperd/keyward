// Bitwarden's encrypted strings. Only the authenticated kinds are read:
//   2.iv|ct|mac  AES-256-CBC + HMAC-SHA256 — every value of the vault;
//   3.ct         RSA-2048-OAEP with SHA-256 (Rsa2048_OaepSha256_B64);
//   4.ct         RSA-2048-OAEP with SHA-1 (Rsa2048_OaepSha1_B64) — what the
//                server and every current client seal organisation keys with.
// RSA-OAEP is itself authenticated (a forged ciphertext fails the padding
// check inside the private-key operation, which reveals nothing).
// Type 0 has no mac and 1 is retired; reading them would hand whoever
// controls the server a padding oracle and the power to edit plaintext
// through the IV (see `authenticated` in crates/vault/src/read.rs). Types 5
// and 6 (RSA-OAEP SHA-256 / SHA-1 with an HMAC-SHA256 tail, `ct|mac`) are
// retired too: no client writes them, and their mac is keyed by a symmetric
// key the RSA layer exists to replace, so it proves nothing a 3 or a 4 does
// not — they are refused by name rather than read with the mac ignored. So a
// value of any other shape is refused outright, never decrypted "as best we
// can".
import { fromB64, fromUtf8, zero, type Bytes } from "./bytes";
import { decryptRsa, decryptSym, importSymKey, type PrivateKey, type SymKey } from "./crypto";
import { fail } from "./errors";

export type EncString =
  | { type: 2; iv: Bytes; ct: Bytes; mac: Bytes }
  | { type: 3 | 4; ct: Bytes };

/// Whether an RSA value's OAEP hash is SHA-256 (type 3) rather than SHA-1
/// (type 4).
export const oaepSha256 = (e: { type: 3 | 4 }): boolean => e.type === 3;

/// boundary: the server's encrypted string, read by its type's digit.
export function parseEncString(s: string): EncString {
  const dot = s.indexOf(".");
  if (dot < 1) return fail("err.encStringMalformed");
  const type = s.slice(0, dot);
  const rest = s.slice(dot + 1);
  switch (type) {
    case "2": {
      const parts = rest.split("|");
      if (parts.length !== 3) return fail("err.encStringMalformed");
      const iv = fromB64(parts[0]!);
      const ct = fromB64(parts[1]!);
      const mac = fromB64(parts[2]!);
      // The sizes are fixed by the format; anything else is not a value we
      // wrote or the official clients did.
      if (iv.length !== 16 || mac.length !== 32 || ct.length === 0 || ct.length % 16 !== 0) {
        return fail("err.encStringMalformed");
      }
      return { type: 2, iv, ct, mac };
    }
    case "3":
    case "4": {
      // Types 3 and 4 have no further parts; a `|` in them is not Bitwarden's.
      if (rest.includes("|")) return fail("err.encStringMalformed");
      const ct = fromB64(rest);
      // RSA-2048: the ciphertext is the modulus's size, exactly.
      if (ct.length !== 256) return fail("err.encStringMalformed");
      return { type: type === "3" ? 3 : 4, ct };
    }
    default:
      return fail("err.encTypeUnsupported", { type });
  }
}

/// A symmetric value's bytes. The caller wipes them once used.
export async function decryptBytes(value: string, key: SymKey): Promise<Bytes> {
  const e = parseEncString(value);
  if (e.type !== 2) return fail("err.encTypeUnsupported", { type: String(e.type) });
  return decryptSym(key, e.iv, e.ct, e.mac);
}

/// A symmetric value as text: for what a list shows (names, logins, hosts).
/// A secret is never read through here outside a copy or a reveal.
export async function decryptString(value: string, key: SymKey): Promise<string> {
  const bytes = await decryptBytes(value, key);
  try {
    return fromUtf8(bytes);
  } finally {
    zero(bytes);
  }
}

/// A key sealed for this account: an organisation's, by RSA-OAEP.
export async function unwrapOrgKey(value: string, privateKey: PrivateKey): Promise<SymKey> {
  const e = parseEncString(value);
  if (e.type === 2) return fail("err.encTypeUnsupported", { type: "2" });
  return importSymKey(await decryptRsa(privateKey, oaepSha256(e), e.ct));
}

/// A key sealed with another symmetric key: the user key under the stretched
/// master key, an item's own key under the user or organisation key.
export async function unwrapSymKey(value: string, key: SymKey): Promise<SymKey> {
  return importSymKey(await decryptBytes(value, key));
}
