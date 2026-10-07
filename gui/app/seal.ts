// What the window's Rust half hands this page — a password, a code, a
// generated one — arrives sealed and is opened here, right before it is shown.
//
// The page opens a session once: an ephemeral ECDH P-256 exchange with the
// Rust half (`window_seal_open`), then an AES-256-GCM key derived with
// HKDF-SHA256 over both public keys. The key cannot be exported, not even by
// this page's own code. A value that comes unsealed is not taken.
import { invoke } from "@tauri-apps/api/core";

const SALT = new TextEncoder().encode("keyward window v1");
const INFO = new TextEncoder().encode("window to webview");

export type SealedValue = { sealed: string };

export function b64(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
  return btoa(s);
}

export function unb64(text: string): Uint8Array<ArrayBuffer> {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/// The session key from an exchange: the page's public key, then the window's,
/// in the info — the key belongs to this exchange and no other.
export async function windowKey(secret: ArrayBuffer, page: Uint8Array<ArrayBuffer>, window: Uint8Array<ArrayBuffer>, usage: KeyUsage): Promise<CryptoKey> {
  const info = new Uint8Array(INFO.length + page.length + window.length);
  info.set(INFO, 0);
  info.set(page, INFO.length);
  info.set(window, INFO.length + page.length);
  const ikm = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: SALT, info }, ikm, { name: "AES-GCM", length: 256 }, false, [usage]);
}

async function open(): Promise<CryptoKey> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const page = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const reply = await invoke<string>("window_seal_open", { public: b64(page) });
  const theirs = unb64(reply);
  const windowPublic = await crypto.subtle.importKey("raw", theirs, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = await crypto.subtle.deriveBits({ name: "ECDH", public: windowPublic }, pair.privateKey, 256);
  return windowKey(secret, page, theirs, "decrypt");
}

let session: Promise<CryptoKey> | null = null;

function sealSession(): Promise<CryptoKey> {
  if (!session) {
    session = open().catch((e) => {
      session = null;
      throw e;
    });
  }
  return session;
}

/// Calls a command that returns a secret and opens its answer. The session is
/// made sure of first: the window seals only for a page that has opened one.
export async function invokeSecret(cmd: string, args: Record<string, unknown>): Promise<string> {
  await sealSession();
  return openSecret(await invoke<SealedValue>(cmd, args));
}

/// Opens a sealed value. Anything else is refused: a value that is not sealed
/// did not come through the session.
export async function openSecret(value: unknown): Promise<string> {
  const sealed = (value as SealedValue | null)?.sealed;
  if (typeof sealed !== "string") throw new Error("err.channelRequired");
  const key = await sealSession();
  const bytes = unb64(sealed);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.subarray(0, 12) }, key, bytes.subarray(12));
  return new TextDecoder().decode(plain);
}
