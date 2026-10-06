// From the master password to the master key, the password hash the server
// checks, and the stretched pair that opens the user key — the same steps as
// crates/bw/src/crypto.rs, so both clients derive the same bytes.
import { argon2Here, type Argon2Params } from "./argon2";
import { toB64, utf8, zero, type Bytes } from "./bytes";
import { sha256, stretch, type SymKey } from "./crypto";
import { fail, WebError } from "./errors";

/// Which derivation an account's KDF is.
export enum KdfKind {
  Pbkdf2 = "pbkdf2",
  Argon2id = "argon2id",
}
export type Kdf =
  | { kind: KdfKind.Pbkdf2; iterations: number }
  | { kind: KdfKind.Argon2id; iterations: number; memoryMiB: number; parallelism: number };

/// The bounds a KDF's parameters must keep, whoever sent them. The server
/// (prelogin) names the parameters, and a server that is not honest — or
/// not the account's — could otherwise ask for one PBKDF2 iteration (a
/// password hash anyone can brute-force from the wire) or for gigabytes of
/// Argon2 memory (a tab that dies). The floors are Bitwarden's own minimums,
/// at least as strict as crates/vault/src/account.rs `validate_kdf`; the
/// ceilings are what a browser tab can do.
export const KDF_BOUNDS = {
  pbkdf2Iterations: { min: 100_000, max: 2_000_000 },
  argon2Iterations: { min: 2, max: 10 },
  argon2MemoryMiB: { min: 16, max: 1024 },
  argon2Parallelism: { min: 1, max: 16 },
} as const;

function within(param: keyof typeof KDF_BOUNDS, v: number): void {
  const { min, max } = KDF_BOUNDS[param];
  // Not a number, not whole, or outside: the same refusal, said with the
  // bounds (the parameters are not secret).
  if (!(Number.isInteger(v) && v >= min && v <= max)) fail("err.kdfOutOfRange", { param, min, max });
}

/// Refuses a KDF whose parameters are outside `KDF_BOUNDS`; returns it as is
/// otherwise. Checked where the parameters come in (prelogin) and again
/// right before every derivation.
export function checkKdf(kdf: Kdf): Kdf {
  if (kdf.kind === KdfKind.Pbkdf2) {
    within("pbkdf2Iterations", kdf.iterations);
  } else if (kdf.kind === KdfKind.Argon2id) {
    within("argon2Iterations", kdf.iterations);
    within("argon2MemoryMiB", kdf.memoryMiB);
    within("argon2Parallelism", kdf.parallelism);
  } else {
    fail("err.kdfUnknown", { reason: "kdf" });
  }
  return kdf;
}

/// The salt is the login, trimmed and in lower case: the protocol says so,
/// and a different spelling derives a different key.
export const normalEmail = (email: string) => email.trim().toLowerCase();

/// The master key, 32 bytes. The caller wipes it as soon as the hash and the
/// stretched pair are made from it.
export async function deriveMasterKey(password: string, email: string, kdf: Kdf): Promise<Bytes> {
  checkKdf(kdf);
  const pw = utf8(password);
  const salt = utf8(normalEmail(email));
  try {
    if (kdf.kind === KdfKind.Pbkdf2) {
      const base = await globalThis.crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
      return new Uint8Array(
        await globalThis.crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: kdf.iterations }, base, 256),
      );
    }
    // Argon2's salt is the login's SHA-256: Argon2 wants a salt of fixed
    // length, and logins have any.
    const argonSalt = await sha256(salt);
    try {
      return await argon2(pw, argonSalt, kdf);
    } finally {
      zero(argonSalt);
    }
  } finally {
    zero(pw, salt);
  }
}

/// Argon2id in a worker where the page can start one (a browser), so the
/// window does not freeze for the second it takes; on this thread where it
/// cannot (tests under Node, which has no `Worker`). A worker that fails or
/// answers without a key is a refusal, never a retry on the page's thread.
async function argon2(pw: Bytes, salt: Bytes, params: Argon2Params): Promise<Bytes> {
  if (typeof globalThis.Worker !== "function" || typeof globalThis.document === "undefined") {
    return argon2Here(pw, salt, params);
  }
  // Copies to transfer: the caller's buffers stay the caller's to wipe, and
  // the copies leave this thread detached.
  const pwc = pw.slice();
  const saltc = salt.slice();
  let worker: Worker;
  try {
    // boundary: the Worker's own option, not a state.
    worker = new Worker(new URL("./argon2.worker.ts", import.meta.url), { type: "module" });
  } catch {
    zero(pwc, saltc);
    return fail("err.kdfFailed", { reason: "worker" });
  }
  try {
    return await new Promise<Bytes>((resolve, reject) => {
      worker.onmessage = (ev: MessageEvent<{ mk: Bytes | null }>) => {
        const mk = ev.data?.mk;
        if (mk instanceof Uint8Array && mk.length === 32) resolve(mk);
        else {
          if (mk instanceof Uint8Array) zero(mk);
          reject(kdfFailed("argon2"));
        }
      };
      worker.onerror = () => reject(kdfFailed("worker"));
      worker.onmessageerror = () => reject(kdfFailed("message"));
      worker.postMessage({ pw: pwc, salt: saltc, params: { iterations: params.iterations, memoryMiB: params.memoryMiB, parallelism: params.parallelism } }, [
        pwc.buffer,
        saltc.buffer,
      ]);
    });
  } finally {
    worker.terminate();
    // Detached by the transfer (then a no-op), or still here if posting failed.
    zero(pwc, saltc);
  }
}

const kdfFailed = (reason: string) => new WebError("err.kdfFailed", { reason });

/// What goes to the server instead of the password: one PBKDF2 iteration of
/// the master key salted with the password, so the server cannot get from it
/// to the key.
export async function masterPasswordHash(masterKey: Bytes, password: string): Promise<string> {
  const pw = utf8(password);
  try {
    const base = await globalThis.crypto.subtle.importKey("raw", masterKey, "PBKDF2", false, ["deriveBits"]);
    const out = new Uint8Array(
      await globalThis.crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: pw, iterations: 1 }, base, 256),
    );
    try {
      return toB64(out);
    } finally {
      zero(out);
    }
  } finally {
    zero(pw);
  }
}

/// Everything a login and an unlock need from the password, in one pass: the
/// master key exists only inside this function.
export async function fromPassword(password: string, email: string, kdf: Kdf): Promise<{ hash: string; stretched: SymKey }> {
  const mk = await deriveMasterKey(password, email, kdf);
  try {
    return { hash: await masterPasswordHash(mk, password), stretched: await stretch(mk) };
  } finally {
    zero(mk);
  }
}
