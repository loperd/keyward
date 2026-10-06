// Argon2id itself, in whichever thread runs it: the page's (tests, a page
// without workers) or argon2.worker.ts's. The caller owns and wipes its
// inputs; the output is a buffer of ours (hash-wasm's own view is wiped).
import { argon2id } from "hash-wasm";
import { zero, type Bytes } from "./bytes";

export type Argon2Params = { iterations: number; memoryMiB: number; parallelism: number };

export async function argon2Here(pw: Bytes, salt: Bytes, p: Argon2Params): Promise<Bytes> {
  const out = await argon2id({
    password: pw,
    salt,
    iterations: p.iterations,
    memorySize: p.memoryMiB * 1024,
    parallelism: p.parallelism,
    hashLength: 32,
    outputType: "binary",
  });
  const mk = new Uint8Array(out);
  zero(out);
  return mk;
}
