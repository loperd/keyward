// Bytes and their spellings. Decrypted bytes are wiped with `zero` the moment
// they have served: a JavaScript string cannot be wiped, a Uint8Array can, so
// a secret stays bytes for as long as the work allows.
import { fail } from "./errors";

/// Bytes over a plain ArrayBuffer: what WebCrypto accepts as a BufferSource.
export type Bytes = Uint8Array<ArrayBuffer>;

/// Wipes a buffer. Called on every key and every decrypted secret right after
/// use, so a later heap snapshot finds zeros where it was.
export function zero(...bufs: (Uint8Array | ArrayBuffer | null | undefined)[]): void {
  for (const b of bufs) {
    if (!b) continue;
    (b instanceof Uint8Array ? b : new Uint8Array(b)).fill(0);
  }
}

const STD = /^[A-Za-z0-9+/]*={0,2}$/;

/// Strict standard base64: a server value that is not base64 is corrupt data,
/// not something to guess at.
export function fromB64(s: string): Bytes {
  if (s.length % 4 !== 0 || !STD.test(s)) fail("err.encStringMalformed");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toB64(b: Bytes): string {
  let bin = "";
  for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]!);
  return btoa(bin);
}

export function toB64Url(b: Bytes): string {
  return toB64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64Url(s: string): Bytes {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  return fromB64(std + "=".repeat((4 - (std.length % 4)) % 4));
}

const encoder = new TextEncoder();
/// Fatal decoding: bytes that are not UTF-8 came out of a wrong key or a
/// corrupt value, and a replacement character would hide that.
const decoder = new TextDecoder("utf-8", { fatal: true });

export const utf8 = (s: string): Bytes => encoder.encode(s);

export function fromUtf8(b: Bytes): string {
  try {
    return decoder.decode(b);
  } catch {
    return fail("err.decryptFailed", { reason: "utf8" });
  }
}

export function concat(...parts: Bytes[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/// Equality that takes the same time wherever the first difference is.
export function constantTimeEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
