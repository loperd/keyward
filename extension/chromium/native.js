// The one road to keyward: the native messaging host `me.loper`,
// which speaks to the daemon. It knows four requests and nothing else.
//
// Nothing on this road is in the clear. Every request opens a port of its own
// and, on it, a session: an ephemeral ECDH P-256 exchange, two keys derived
// with HKDF-SHA256 (salt `keyward bridge v1`, the direction and both public
// keys in the info), then the request and the answer sealed with AES-256-GCM,
// a counter of each direction for the nonce. WebCrypto does all of it; the
// host does the same in Rust (`crates/passkey-host/src/bridge.rs`).

const HOST = "me.loper";
const SALT = new TextEncoder().encode("keyward bridge v1");
const TO_HOST = new TextEncoder().encode("extension to host");
const TO_EXTENSION = new TextEncoder().encode("host to extension");

function b64(bytes) {
  const view = new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
  return btoa(s);
}

function unb64(text) {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function nonce(counter) {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(4, BigInt(counter));
  return n;
}

async function sessionKeys(secret, extension, host) {
  const ikm = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  const derive = (label, usage) =>
    crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: SALT, info: concat(label, extension, host) },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      [usage],
    );
  return { toHost: await derive(TO_HOST, "encrypt"), toExtension: await derive(TO_EXTENSION, "decrypt") };
}

// One request over a sealed session of its own; resolves with the host's
// answer, `{ ok, ... }`.
export function native(message) {
  return new Promise((resolve, reject) => {
    let port;
    let done = false;
    const finish = (fn, value) => {
      if (done) return;
      done = true;
      try {
        port?.disconnect();
      } catch {}
      fn(value);
    };
    (async () => {
      const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
      const mine = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
      let keys = null;
      port = chrome.runtime.connectNative(HOST);
      port.onDisconnect.addListener(() => {
        finish(reject, new Error(chrome.runtime.lastError?.message || "the bridge closed the connection"));
      });
      port.onMessage.addListener(async (reply) => {
        try {
          if (!keys) {
            // The host's half of the exchange, or a plain refusal.
            if (typeof reply?.hello !== "string") return finish(resolve, reply);
            const theirs = unb64(reply.hello);
            const hostKey = await crypto.subtle.importKey("raw", theirs, { name: "ECDH", namedCurve: "P-256" }, false, []);
            const secret = await crypto.subtle.deriveBits({ name: "ECDH", public: hostKey }, pair.privateKey, 256);
            keys = await sessionKeys(new Uint8Array(secret), mine, theirs);
            const plain = new TextEncoder().encode(JSON.stringify({ id: 1, ...message }));
            const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce(0) }, keys.toHost, plain);
            port.postMessage({ sealed: b64(sealed) });
            return;
          }
          if (typeof reply?.sealed !== "string") return finish(resolve, reply);
          const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce(0) }, keys.toExtension, unb64(reply.sealed));
          finish(resolve, JSON.parse(new TextDecoder().decode(plain)));
        } catch (e) {
          finish(reject, e);
        }
      });
      port.postMessage({ hello: b64(mine) });
    })().catch((e) => finish(reject, e));
  });
}

// The secure contexts WebAuthn itself allows: https, and http on localhost.
export function secureOrigin(origin) {
  let url;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  if (url.protocol === "https:") return true;
  const host = url.hostname;
  return url.protocol === "http:" && (host === "localhost" || host.endsWith(".localhost"));
}
