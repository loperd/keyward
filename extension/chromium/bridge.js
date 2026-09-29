// The bridge between the page's world and the extension, in the isolated
// world of the top frame.
//
// It passes a request on and an answer back, and adds nothing of the page's
// to what the extension trusts: the extension learns the origin from the
// browser (`sender`), not from here. Only messages from this very window are
// taken — a frame inside the page posting into it is ignored.
(() => {
  "use strict";

  const TAG = "keyward-passkeys";
  const origin = window.location.origin;
  // The extension's flow for each of the page's requests.
  const flows = new Map();

  const reply = (id, answer) => window.postMessage({ tag: TAG, dir: "reply", id, ...answer }, origin);

  window.addEventListener("message", async (event) => {
    if (event.source !== window) return;
    const d = event.data;
    if (!d || d.tag !== TAG) return;

    if (d.dir === "abort") {
      for (const [flow, id] of flows) {
        if (id !== d.id) continue;
        flows.delete(flow);
        chrome.runtime.sendMessage({ kind: "abort", flow }).catch((e) => console.warn("keyward: the abort did not reach the extension", e));
      }
      return;
    }
    if (d.dir !== "ask" || (d.kind !== "get" && d.kind !== "create")) return;

    let begun;
    try {
      begun = await chrome.runtime.sendMessage({ kind: d.kind, request: d.request });
    } catch (e) {
      // The extension was reloaded or is gone: the browser does it itself.
      console.warn("keyward: the extension is not reachable; the browser handles this request", e);
      return reply(d.id, { fallback: true });
    }
    if (!begun || !begun.flow) return reply(d.id, begun && begun.error ? begun : { fallback: true });
    flows.set(begun.flow, d.id);
  });

  // The answer comes from the chooser once the person has decided.
  chrome.runtime.onMessage.addListener((msg, sender) => {
    if (sender.id !== chrome.runtime.id || !msg || msg.tag !== "keyward-result") return;
    const id = flows.get(msg.flow);
    if (id === undefined) return;
    flows.delete(msg.flow);
    reply(id, msg.result || { error: "NotAllowedError" });
  });
})();
