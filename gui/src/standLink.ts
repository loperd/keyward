// The stand's half of a plugin's sealed link, as `keyward-ui`'s `link.rs`
// speaks it: ECDH P-256, HKDF-SHA256, AES-256-GCM, two lanes with a counter
// each. The page cannot tell the stand from a plugin, which is the point: the
// screens are photographed against the real protocol.

const SALT = new TextEncoder().encode("keyward terminal v1");
const enc = new TextEncoder();

export function b64(bytes: Uint8Array): string {
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

function nonce(counter: number): Uint8Array<ArrayBuffer> {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(4, BigInt(counter));
  return n;
}

type Lane = { open: CryptoKey; seal: CryptoKey; counter: number };
export type LaneName = "input" | "output";

async function laneKeys(secret: ArrayBuffer, lane: string, page: Uint8Array, mine: Uint8Array): Promise<Lane> {
  const derive = async (direction: string, usage: KeyUsage) => {
    const label = enc.encode(`${direction} ${lane}`);
    const info = new Uint8Array(label.length + page.length + mine.length);
    info.set(label, 0);
    info.set(page, label.length);
    info.set(mine, label.length + page.length);
    const ikm = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: SALT, info }, ikm, { name: "AES-GCM", length: 256 }, false, [usage]);
  };
  return { open: await derive("page to plugin", "decrypt"), seal: await derive("plugin to page", "encrypt"), counter: 0 };
}

/// A plugin's two link operations for the stand: `link` accepts the page's
/// key, `call` opens a request, hands it to `answer` and seals what it says.
/// `gone` is the error a forgotten link is refused with.
export function standLink<L>(
  gone: string,
  fresh: () => L,
  answer: (state: L, lane: LaneName, req: Record<string, unknown>) => unknown,
): { link: (p: Record<string, unknown>) => Promise<unknown>; call: (p: Record<string, unknown>) => Promise<unknown>; each: () => L[] } {
  const links = new Map<string, { input: Lane; output: Lane; state: L }>();
  let ids = 0;
  return {
    link: async ({ public: pagePublic }) => {
      const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
      const mine = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
      const page = unb64(String(pagePublic));
      const theirs = await crypto.subtle.importKey("raw", page, { name: "ECDH", namedCurve: "P-256" }, false, []);
      const secret = await crypto.subtle.deriveBits({ name: "ECDH", public: theirs }, pair.privateKey, 256);
      ids += 1;
      const id = `l${ids}`;
      links.set(id, { input: await laneKeys(secret, "input", page, mine), output: await laneKeys(secret, "output", page, mine), state: fresh() });
      return { link: id, public: b64(mine) };
    },
    call: async ({ link: id, lane: name, sealed }) => {
      const link = links.get(String(id));
      if (!link) throw gone;
      const laneName: LaneName = name === "output" ? "output" : "input";
      const lane = link[laneName];
      const aad = enc.encode(laneName);
      const n = nonce(lane.counter);
      let plain: Uint8Array;
      try {
        plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: n, additionalData: aad }, lane.open, unb64(String(sealed))));
      } catch {
        throw "err.channelFailed";
      }
      const req = JSON.parse(new TextDecoder().decode(plain)) as Record<string, unknown>;
      const result = await answer(link.state, laneName, req);
      const out = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: n, additionalData: aad }, lane.seal, enc.encode(JSON.stringify(result ?? null))));
      lane.counter += 1;
      return { sealed: b64(out) };
    },
    each: () => [...links.values()].map((l) => l.state),
  };
}
