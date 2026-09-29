// keyward's stand-in for navigator.credentials, in the page's own world.
//
// It runs at document_start, before any script of the page, and takes its own
// copies of everything it relies on: a page that later swaps btoa, atob or
// postMessage cannot bend what this code does with them.
//
// What it hands over: the raw parts of a WebAuthn request — the challenge, the
// site the page names, the identifiers it allows. What it does not hand over:
// the origin. The extension takes that from the browser, never from the page,
// and the daemon builds the client data itself.
//
// What it leaves to the browser: anything but a passkey request, the
// autofill-style "conditional" requests (they fire on page load; a Touch ID
// prompt for them would come out of nowhere), a site that insists on a
// security key, and every case where keyward has nothing to offer or the
// person chooses "Another way".
(() => {
  "use strict";

  const creds = navigator.credentials;
  if (!creds || window.top !== window || typeof PublicKeyCredential === "undefined") return;

  const TAG = "keyward-passkeys";
  const nativeGet = creds.get.bind(creds);
  const nativeCreate = creds.create.bind(creds);
  const post = window.postMessage.bind(window);
  const listen = window.addEventListener.bind(window);
  const toB64 = window.btoa.bind(window);
  const fromB64 = window.atob.bind(window);
  const origin = window.location.origin;
  const fromCharCode = String.fromCharCode;
  const create = Object.create;
  const freeze = Object.freeze;
  const DOMEx = DOMException;
  const AssertionProto = AuthenticatorAssertionResponse.prototype;
  const AttestationProto = AuthenticatorAttestationResponse.prototype;
  const CredentialProto = PublicKeyCredential.prototype;

  const bytes = (src) =>
    ArrayBuffer.isView(src) ? new Uint8Array(src.buffer, src.byteOffset, src.byteLength) : new Uint8Array(src);

  const b64u = (src) => {
    const b = bytes(src);
    let s = "";
    for (let i = 0; i < b.length; i++) s += fromCharCode(b[i]);
    return toB64(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const buffer = (text) => {
    let s = String(text).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = fromB64(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };

  let seq = 0;
  const waiting = new Map();

  listen("message", (event) => {
    if (event.source !== window) return;
    const d = event.data;
    if (!d || d.tag !== TAG || d.dir !== "reply") return;
    const w = waiting.get(d.id);
    if (!w) return;
    waiting.delete(d.id);
    w(d);
  });

  // One request to the extension; resolves with its answer.
  const ask = (kind, request, signal) =>
    new Promise((resolve, reject) => {
      const id = ++seq;
      if (signal) {
        if (signal.aborted) return reject(signal.reason ?? new DOMEx("The operation was aborted.", "AbortError"));
        signal.addEventListener(
          "abort",
          () => {
            if (!waiting.delete(id)) return;
            post({ tag: TAG, dir: "abort", id }, origin);
            reject(signal.reason ?? new DOMEx("The operation was aborted.", "AbortError"));
          },
          { once: true },
        );
      }
      waiting.set(id, resolve);
      post({ tag: TAG, dir: "ask", id, kind, request }, origin);
    });

  const refusal = (answer) =>
    new DOMEx(
      answer.error === "InvalidStateError"
        ? "The authenticator already holds a passkey for this account."
        : "The operation either timed out or was not allowed.",
      answer.error || "NotAllowedError",
    );

  // Plain objects dressed as the browser's own: the prototype for
  // `instanceof`, own properties for the values (the prototype's getters
  // would throw on an object the browser did not make).
  const value = (v) => ({ value: v, enumerable: true });

  const assertion = (signed) => {
    const a = signed.assertion;
    const json = freeze({
      id: a.credential_id,
      rawId: a.credential_id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: signed.client_data_json,
        authenticatorData: a.authenticator_data,
        signature: a.signature,
        userHandle: a.user_handle ?? undefined,
      },
    });
    const response = create(AssertionProto, {
      clientDataJSON: value(buffer(signed.client_data_json)),
      authenticatorData: value(buffer(a.authenticator_data)),
      signature: value(buffer(a.signature)),
      userHandle: value(a.user_handle ? buffer(a.user_handle) : null),
    });
    return create(CredentialProto, {
      id: value(a.credential_id),
      rawId: value(buffer(a.credential_id)),
      type: value("public-key"),
      authenticatorAttachment: value("platform"),
      response: value(response),
      getClientExtensionResults: { value: () => ({}) },
      toJSON: { value: () => json },
    });
  };

  const attestation = (registered, wantsCredProps) => {
    const a = registered.attestation;
    const transports = ["hybrid", "internal"];
    const extensions = wantsCredProps ? { credProps: { rk: true } } : {};
    const json = freeze({
      id: a.credential_id,
      rawId: a.credential_id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: extensions,
      response: {
        clientDataJSON: registered.client_data_json,
        attestationObject: a.attestation_object,
        authenticatorData: a.authenticator_data,
        transports,
        publicKey: a.public_key,
        publicKeyAlgorithm: a.algorithm,
      },
    });
    const response = create(AttestationProto, {
      clientDataJSON: value(buffer(registered.client_data_json)),
      attestationObject: value(buffer(a.attestation_object)),
      getTransports: { value: () => transports.slice() },
      getAuthenticatorData: { value: () => buffer(a.authenticator_data) },
      getPublicKey: { value: () => buffer(a.public_key) },
      getPublicKeyAlgorithm: { value: () => a.algorithm },
    });
    return create(CredentialProto, {
      id: value(a.credential_id),
      rawId: value(buffer(a.credential_id)),
      type: value("public-key"),
      authenticatorAttachment: value("platform"),
      response: value(response),
      getClientExtensionResults: { value: () => ({ ...extensions }) },
      toJSON: { value: () => json },
    });
  };

  const get = function get(options) {
    const pk = options && options.publicKey;
    if (!pk || options.mediation === "conditional") return nativeGet(options);
    let request;
    try {
      request = {
        rp_id: pk.rpId ?? null,
        challenge: b64u(pk.challenge),
        allow_credentials: (pk.allowCredentials || []).map((c) => b64u(c.id)),
      };
    } catch {
      return nativeGet(options);
    }
    return ask("get", request, options.signal).then((answer) => {
      if (answer.fallback) return nativeGet(options);
      if (answer.signed) return assertion(answer.signed);
      throw refusal(answer);
    });
  };

  const make = function createCredential(options) {
    const pk = options && options.publicKey;
    if (!pk) return nativeCreate(options);
    const selection = pk.authenticatorSelection || {};
    // A site that wants a security key gets the browser's own dialog.
    if (selection.authenticatorAttachment === "cross-platform") return nativeCreate(options);
    let request;
    try {
      request = {
        rp_id: pk.rp?.id ?? null,
        rp_name: pk.rp?.name ?? null,
        user_id: b64u(pk.user.id),
        user_name: pk.user?.name ?? null,
        user_display_name: pk.user?.displayName ?? null,
        challenge: b64u(pk.challenge),
        algorithms: (pk.pubKeyCredParams || []).map((p) => p.alg),
        exclude_credentials: (pk.excludeCredentials || []).map((c) => b64u(c.id)),
        discoverable: selection.residentKey !== "discouraged" || selection.requireResidentKey === true,
      };
    } catch {
      return nativeCreate(options);
    }
    const wantsCredProps = !!pk.extensions?.credProps;
    return ask("create", request, options.signal).then((answer) => {
      if (answer.fallback) return nativeCreate(options);
      if (answer.registered) return attestation(answer.registered, wantsCredProps);
      throw refusal(answer);
    });
  };

  // Look like the originals to a page that checks.
  const native = (fn, name) => {
    Object.defineProperty(fn, "name", { value: name });
    Object.defineProperty(fn, "toString", { value: () => `function ${name}() { [native code] }` });
    return fn;
  };
  Object.defineProperty(creds, "get", { value: native(get, "get"), configurable: true, writable: true });
  Object.defineProperty(creds, "create", { value: native(make, "create"), configurable: true, writable: true });
})();
