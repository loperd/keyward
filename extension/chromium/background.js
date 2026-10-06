// The extension's service worker: it checks who is asking, asks the daemon
// whether keyward has anything to offer, and opens the chooser.
//
// The origin is the browser's word, not the page's: `sender.origin` of the top
// frame. It is kept with the flow in session storage (memory only, out of
// reach of content scripts) and is the only origin the chooser ever sends.
//
// The flow itself lives in the chooser window: a service worker is put to
// sleep after half a minute idle, and a person deciding takes longer than
// that.

import { native, secureOrigin } from "./native.js";

const FLOW = "flow:";
const MAX_IDS = 64;
const MAX_TEXT = 2048;

const text = (v) => (typeof v === "string" && v.length <= MAX_TEXT ? v : null);
const ids = (v) => (Array.isArray(v) ? v.slice(0, MAX_IDS).map(text).filter(Boolean) : []);

// Only the fields the daemon takes, each of the type it takes.
function sanitize(kind, r) {
  r = r && typeof r === "object" ? r : {};
  const base = { rp_id: text(r.rp_id), challenge: text(r.challenge) };
  if (kind === "get") return { ...base, allow_credentials: ids(r.allow_credentials) };
  return {
    ...base,
    rp_name: text(r.rp_name),
    user_id: text(r.user_id),
    user_name: text(r.user_name),
    user_display_name: text(r.user_display_name),
    algorithms: Array.isArray(r.algorithms) ? r.algorithms.filter(Number.isInteger).slice(0, 16) : [],
    exclude_credentials: ids(r.exclude_credentials),
    discoverable: r.discoverable !== false,
  };
}

async function flowsWhere(pred) {
  const all = await chrome.storage.session.get(null);
  return Object.entries(all).filter(([k, f]) => k.startsWith(FLOW) && pred(f));
}

// Tells the page its request is over and forgets the flow.
async function end(flow, result) {
  await chrome.storage.session.remove(FLOW + flow.id);
  chrome.tabs
    .sendMessage(flow.tabId, { tag: "keyward-result", flow: flow.id, result }, { frameId: 0 })
    .catch((e) => console.warn("keyward: the page did not take the answer", e));
}

async function closeFlow(flow, result) {
  await end(flow, result);
  if (flow.windowId) chrome.windows.remove(flow.windowId).catch((e) => console.warn("keyward: the chooser did not close", e));
}

async function openChooser(id, parentWindowId) {
  const width = 420;
  const height = 520;
  let left, top;
  try {
    const parent = await chrome.windows.get(parentWindowId);
    left = Math.round(parent.left + (parent.width - width) / 2);
    top = Math.round(parent.top + Math.min(120, (parent.height - height) / 2));
  } catch {}
  return chrome.windows.create({
    url: chrome.runtime.getURL(`chooser.html#${id}`),
    type: "popup",
    width,
    height,
    left,
    top,
    focused: true,
  });
}

async function begin(kind, raw, sender) {
  if (!sender.tab || sender.frameId !== 0) return { fallback: true };
  const origin = sender.origin || new URL(sender.url).origin;
  if (!secureOrigin(origin)) return { fallback: true };
  const request = sanitize(kind, raw);
  if (!request.challenge || (kind === "create" && !request.user_id)) return { fallback: true };

  const sign_in = { origin, rp_id: request.rp_id, challenge: request.challenge };
  let lookup;
  try {
    lookup =
      kind === "get"
        ? await native({ op: "offers", sign_in: { ...sign_in, allow_credentials: request.allow_credentials } })
        : await native({ op: "homes", sign_in });
  } catch (e) {
    // No bridge installed, or keyward not there: the browser does it itself.
    console.warn("keyward: the bridge is not reachable; the browser handles this request", e);
    return { fallback: true };
  }
  // A locked vault and an extension not paired yet both open the chooser:
  // the person can do something about either, and a pairing's words have to
  // be seen to be compared.
  const unpaired = !lookup.ok && lookup.code === "err.extensionNotPaired";
  const locked = !lookup.ok && (lookup.code === "err.vaultLocked" || unpaired);
  if (!lookup.ok && !locked) {
    console.warn("keyward: the daemon refused; the browser handles this request", lookup.code);
    return { fallback: true };
  }
  // No passkey for the site in keyward: the chooser still opens and says so,
  // with the browser's own way one press away. Stepping aside silently left
  // a person unsure whether keyward was there at all.

  // One flow per tab: a new request ends an older one.
  for (const [, old] of await flowsWhere((f) => f.tabId === sender.tab.id)) {
    await closeFlow(old, { error: "NotAllowedError" });
  }

  const id = crypto.randomUUID();
  const flow = {
    id,
    kind,
    tabId: sender.tab.id,
    origin,
    request,
    locked,
    // The daemon's words for why, rendered: a pairing's carries the key's
    // five words.
    unpaired: unpaired ? { words: Array.isArray(lookup.words) ? lookup.words : [], expires: Number(lookup.expires) || 0 } : null,
    offers: kind === "get" && lookup.ok ? lookup.offers : [],
    homes: kind === "create" && lookup.ok ? lookup.homes : [],
  };
  await chrome.storage.session.set({ [FLOW + id]: flow });
  const win = await openChooser(id, sender.tab.windowId);
  flow.windowId = win.id;
  await chrome.storage.session.set({ [FLOW + id]: flow });
  return { flow: id };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !msg) return;
  if (msg.kind === "get" || msg.kind === "create") {
    begin(msg.kind, msg.request, sender).then(sendResponse, (e) => {
      console.error("keyward: a request fell over; the browser handles it", e);
      sendResponse({ fallback: true });
    });
    return true;
  }
  if (msg.kind === "abort" && sender.tab) {
    flowsWhere((f) => f.id === msg.flow && f.tabId === sender.tab.id).then(async (found) => {
      for (const [, f] of found) {
        await chrome.storage.session.remove(FLOW + f.id);
        if (f.windowId) chrome.windows.remove(f.windowId).catch(() => {});
      }
    });
  }
});

// The chooser closed without an answer: the page hears "not allowed", as
// from the browser's own dialog.
chrome.windows.onRemoved.addListener(async (windowId) => {
  for (const [, f] of await flowsWhere((f) => f.windowId === windowId)) {
    await end(f, { error: "NotAllowedError" });
  }
});

// The tab went away: its chooser has nothing left to answer.
chrome.tabs.onRemoved.addListener(async (tabId) => {
  for (const [, f] of await flowsWhere((f) => f.tabId === tabId)) {
    await chrome.storage.session.remove(FLOW + f.id);
    if (f.windowId) chrome.windows.remove(f.windowId).catch(() => {});
  }
});

// Session storage is for trusted contexts only: no content script reads a
// flow.
chrome.storage.session.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" });
