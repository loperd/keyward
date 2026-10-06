// The page's half of a sealed link to a plugin — `crates/ssh-client/src/link.rs`
// is the plugin's.
//
// What a plugin's screen carries may be whatever a person types and whatever
// a server prints: a shell, a cluster's logs, a manifest with a secret in it.
// It crosses the window's Rust half and the daemon on its way to the plugin,
// and neither has any business reading it: the page and the plugin make a key
// of their own (ECDH P-256, HKDF-SHA256, AES-256-GCM) and only ciphertext
// travels in between. The keys cannot be exported, not even by this page's
// own code.
//
// A link has two lanes, input and output: a long-poll for output and a
// keystroke travel at the same time and would overtake each other. Within a
// lane the next request goes only after the answer to the last one, and the
// nonce is the exchange's number — a message replayed, dropped or reordered
// does not open.
import { call } from "@keyward/plugins/call";

/// The plugin's operations the link goes through: one that makes a link, and
/// one that carries a sealed request on it.
export type LinkOps = { plugin: string; link: string; call: string };

// The label of the exchange, shared with the plugin's half. It says terminal
// because the terminal was the first to speak this way; changing it would
// change every key.
const SALT = new TextEncoder().encode("keyward terminal v1");
const TO_PLUGIN = "page to plugin";
const TO_PAGE = "plugin to page";

export type LaneName = "input" | "output";

function b64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function unb64(text: string): Uint8Array<ArrayBuffer> {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64(bytes: Uint8Array): string {
  return b64(bytes);
}

function nonce(counter: number): Uint8Array<ArrayBuffer> {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(4, BigInt(counter));
  return n;
}

async function key(secret: ArrayBuffer, direction: string, lane: LaneName, page: Uint8Array, plugin: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  const label = new TextEncoder().encode(`${direction} ${lane}`);
  const info = new Uint8Array(label.length + page.length + plugin.length);
  info.set(label, 0);
  info.set(page, label.length);
  info.set(plugin, label.length + page.length);
  const ikm = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: SALT, info }, ikm, { name: "AES-GCM", length: 256 }, false, [usage]);
}

/// A request the plugin answered with a refusal. Sealed like any answer, so
/// the lane is still in step; the message is a key for `tError`.
export class Refused extends Error {}

/// One lane: requests one at a time, in order.
class Lane {
  private counter = 0;
  private queue: Promise<unknown> = Promise.resolve();
  private readonly aad: Uint8Array<ArrayBuffer>;

  constructor(
    private readonly ops: LinkOps,
    private readonly link: string,
    private readonly name: LaneName,
    private readonly seal: CryptoKey,
    private readonly open: CryptoKey,
  ) {
    this.aad = new TextEncoder().encode(name);
  }

  /// Sends one request and opens its answer. A `Refused` is the plugin's
  /// word; anything else means the lane can no longer be trusted to be in
  /// step, and the link has to be made anew.
  request<T>(body: unknown): Promise<T> {
    const run = async (): Promise<T> => {
      const n = nonce(this.counter);
      const plain = new TextEncoder().encode(JSON.stringify(body));
      const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: n, additionalData: this.aad }, this.seal, plain));
      plain.fill(0);
      const answer = await call<{ sealed: string }>(this.ops.plugin, this.ops.call, { link: this.link, lane: this.name, sealed: b64(sealed) });
      if (typeof answer?.sealed !== "string") throw new Error("err.channelRequired");
      const opened = new Uint8Array(
        await crypto.subtle.decrypt({ name: "AES-GCM", iv: n, additionalData: this.aad }, this.open, unb64(answer.sealed)),
      );
      this.counter += 1;
      const text = new TextDecoder().decode(opened);
      opened.fill(0);
      const value = JSON.parse(text) as T & { error?: string };
      if (value && typeof value === "object" && typeof value.error === "string") throw new Refused(value.error);
      return value;
    };
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => undefined);
    return next;
  }
}

export type Link = { id: string; input: Lane; output: Lane };

/// Makes a link with a plugin: one per tab or screen that talks to it.
export async function openLink(ops: LinkOps): Promise<Link> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const page = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const reply = await call<{ link: string; public: string }>(ops.plugin, ops.link, { public: b64(page) });
  const plugin = unb64(reply.public);
  const theirs = await crypto.subtle.importKey("raw", plugin, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = await crypto.subtle.deriveBits({ name: "ECDH", public: theirs }, pair.privateKey, 256);
  const lane = async (name: LaneName) =>
    new Lane(ops, reply.link, name, await key(secret, TO_PLUGIN, name, page, plugin, "encrypt"), await key(secret, TO_PAGE, name, page, plugin, "decrypt"));
  return { id: reply.link, input: await lane("input"), output: await lane("output") };
}
