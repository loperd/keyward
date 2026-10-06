// One-time codes, RFC 6238 over WebCrypto's HMAC. What the vault's TOTP field
// holds is read as crates/vault/src/lib.rs reads it: an `otpauth://` link
// with its own algorithm, digits and period; `steam://` (and an otpauth link
// for Steam) for Steam Guard's five letters; or a bare seed in any spelling a
// person pastes — base32 with spaces, dashes, padding or lower case, a scrap
// `secret=...&...` of a link, hex, base64. The seed is imported as a
// non-extractable HMAC key and its bytes are wiped at once.
import { zero, type Bytes } from "./bytes";
import { fail } from "./errors";
import { isEnumValue } from "@keyward/core/model/enum";

/// The HMAC hash of a code, by WebCrypto's name.
export enum TotpAlgorithm {
  Sha1 = "SHA-1",
  Sha256 = "SHA-256",
  Sha512 = "SHA-512",
}
/// What an `otpauth://` link is for, by its host.
enum OtpLinkKind {
  Totp = "totp",
  Steam = "steam",
}

export type TotpParams = {
  secret: Bytes;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
  steam: boolean;
};

const STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Strict RFC 4648 base32 without padding. `null` when it is not base32.
export function base32(s: string): Bytes | null {
  // Lengths 1, 3 and 6 (mod 8) cannot come out of whole bytes.
  if (s.length === 0 || [1, 3, 6].includes(s.length % 8)) return null;
  const out = new Uint8Array(Math.floor((s.length * 5) / 8));
  let bits = 0;
  let acc = 0;
  let at = 0;
  for (const c of s) {
    const v = B32.indexOf(c);
    if (v < 0) {
      zero(out);
      return null;
    }
    acc = ((acc << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/// Seed bytes out of whatever a person pasted into the field. The errors
/// describe its shape only — the seed never travels in a message.
export function seedBytes(seed: string): Bytes {
  const lower = seed.toLowerCase();
  const at = lower.indexOf("secret=");
  let tail = at >= 0 ? seed.slice(at + "secret=".length) : seed;
  tail = tail.split("&")[0]!;
  const tight = tail.replace(/\s+/g, "");
  if (tight === "") return fail("err.totpSeedEmpty");

  // 1. base32 — what is meant nine times out of ten.
  const b32 = tight.replace(/[-=]/g, "").toUpperCase();
  const fromB32 = base32(b32);
  if (fromB32 && fromB32.length > 0) return fromB32;
  // 2. Hex, only after base32: "ABCDEF" is lawful base32 as well.
  if (b32.length % 2 === 0 && b32.length >= 16 && /^[0-9A-F]+$/.test(b32)) {
    const out = new Uint8Array(b32.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(b32.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  // 3. base64, either alphabet, padded or not.
  const b64 = tight.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
  if (/^[A-Za-z0-9+/]+$/.test(b64) && b64.length % 4 !== 1) {
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    if (out.length > 0) return out;
  }
  const outside = [...b32].filter((c) => !B32.includes(c)).length;
  if (outside > 0) return fail("err.totpSeedBadAlphabet", { total: b32.length, outside });
  return fail("err.totpSeedTruncated", { total: b32.length });
}

const ALGORITHMS: Record<string, TotpAlgorithm> = { SHA1: TotpAlgorithm.Sha1, SHA256: TotpAlgorithm.Sha256, SHA512: TotpAlgorithm.Sha512 };

/// What the field holds, read into parameters. The secret is the caller's to
/// wipe.
export function parseTotp(field: string): TotpParams {
  const value = field.trim();
  // A bare run of digits is a one-time code saved in place of its secret;
  // hex would read it as a seed and hand out nonsense codes.
  if (value.length >= 6 && value.length <= 10 && /^\d+$/.test(value)) return fail("err.totpLooksLikeCode");

  if (/^steam:\/\//i.test(value)) {
    return { secret: seedBytes(value.slice("steam://".length)), algorithm: TotpAlgorithm.Sha1, digits: 5, period: 30, steam: true };
  }
  if (!/^otpauth:\/\//i.test(value)) {
    return { secret: seedBytes(value), algorithm: TotpAlgorithm.Sha1, digits: 6, period: 30, steam: false };
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return fail("err.totpLinkUnreadable", { reason: "url" });
  }
  const host = url.hostname.toLowerCase();
  if (!isEnumValue(OtpLinkKind, host)) return fail("err.totpLinkUnreadable", { reason: "kind" });
  const kind: OtpLinkKind = host;
  const q = url.searchParams;
  const steam = kind === OtpLinkKind.Steam || (q.get("encoder") ?? "").toLowerCase() === OtpLinkKind.Steam;
  const secret = q.get("secret");
  if (secret === null) return fail("err.totpSeedEmpty");
  const algoName = (q.get("algorithm") ?? "SHA1").toUpperCase().replace("-", "");
  const algorithm = ALGORITHMS[algoName] ?? fail("err.totpLinkUnreadable", { reason: "algorithm" });
  const digits = steam ? 5 : intParam(q.get("digits"), 6, 1, 10, "digits");
  const period = intParam(q.get("period"), 30, 1, 3600, "period");
  return { secret: seedBytes(secret), algorithm: steam ? TotpAlgorithm.Sha1 : algorithm, digits, period, steam };
}

function intParam(v: string | null, absent: number, min: number, max: number, what: string): number {
  if (v === null) return absent;
  if (!/^\d+$/.test(v)) return fail("err.totpLinkUnreadable", { reason: what });
  const n = Number(v);
  if (n < min || n > max) return fail("err.totpLinkUnreadable", { reason: what });
  return n;
}

/// The code at a moment (milliseconds since the epoch). Wipes `p.secret`.
export async function totpAt(p: TotpParams, nowMs: number): Promise<{ code: string; period: number; remaining: number }> {
  try {
    const seconds = Math.floor(nowMs / 1000);
    const counter = Math.floor(seconds / p.period);
    const msg = new Uint8Array(8);
    // 64-bit big-endian counter; JavaScript numbers hold it exactly far past
    // any date that matters.
    new DataView(msg.buffer).setUint32(0, Math.floor(counter / 2 ** 32));
    new DataView(msg.buffer).setUint32(4, counter >>> 0);
    const key = await globalThis.crypto.subtle.importKey("raw", p.secret, { name: "HMAC", hash: p.algorithm }, false, ["sign"]);
    const mac = new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, msg));
    try {
      const off = mac[mac.length - 1]! & 0x0f;
      const bin =
        ((mac[off]! & 0x7f) << 24) | ((mac[off + 1]! & 0xff) << 16) | ((mac[off + 2]! & 0xff) << 8) | (mac[off + 3]! & 0xff);
      let code: string;
      if (p.steam) {
        let v = bin;
        code = "";
        for (let i = 0; i < 5; i++) {
          code += STEAM_ALPHABET[v % STEAM_ALPHABET.length];
          v = Math.floor(v / STEAM_ALPHABET.length);
        }
      } else {
        code = String(bin % 10 ** p.digits).padStart(p.digits, "0");
      }
      return { code, period: p.period, remaining: p.period - (seconds % p.period) };
    } finally {
      zero(mac);
    }
  } finally {
    zero(p.secret);
  }
}
