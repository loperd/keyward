// The chooser: which passkey to sign in with, or where to save a new one.
//
// It shows names only — of vault items and of accounts — and never a secret;
// the private key does not leave the daemon, and the confirmation is Touch ID,
// whose prompt names the site and the account. Every name is put in with
// textContent: an account name at a registration comes from the site.

import { native } from "./native.js";

const t = (key, subs) => chrome.i18n.getMessage(key, subs) || key;
const $ = (id) => document.getElementById(id);
const FLOW = "flow:";

const flowId = location.hash.slice(1);
let flow = null;
let choice = null;
let busy = false;

// A hue for a monogram, away from the violet band the app keeps out of its
// monograms.
function hue(name) {
  let h = 0;
  for (const c of name) h = (h * 31 + c.codePointAt(0)) >>> 0;
  const band = [...Array(360).keys()].filter((d) => d < 195 || d > 310);
  return band[h % band.length];
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

function row(key, title, sub, { fresh = false, chip = null } = {}) {
  const li = el("li", "choice");
  li.tabIndex = 0;
  li.setAttribute("role", "radio");
  li.dataset.key = key;
  const mono = el("span", fresh ? "mono new" : "mono", fresh ? "+" : (title.trim()[0] || "?").toUpperCase());
  if (!fresh) mono.style.setProperty("--h", String(hue(title)));
  const lines = el("span", "lines");
  lines.append(el("b", "", title));
  if (sub) lines.append(el("small", "", sub));
  li.append(mono, lines);
  if (chip) li.append(el("span", "chip", chip));
  li.addEventListener("click", () => pick(key));
  li.addEventListener("keydown", (e) => {
    if (e.key === " ") {
      e.preventDefault();
      pick(key);
    }
  });
  return li;
}

function pick(key) {
  if (busy) return;
  choice = key;
  for (const li of $("choices").children) li.setAttribute("aria-checked", String(li.dataset.key === key));
}

function host() {
  try {
    return new URL(flow.origin).host;
  } catch {
    return flow.origin;
  }
}

function showError(text) {
  $("error").textContent = text;
  $("error").hidden = !text;
}

function setBusy(on) {
  busy = on;
  $("go").disabled = on;
  $("other").disabled = on;
  $("go").textContent = on ? t("waitTouchId") : flow.kind === "get" ? t("signIn") : t("save");
}

async function finish(result) {
  await chrome.storage.session.remove(FLOW + flow.id);
  await chrome.tabs
    .sendMessage(flow.tabId, { tag: "keyward-result", flow: flow.id, result }, { frameId: 0 })
    .catch((e) => console.error("keyward: the page did not take the answer", e));
  window.close();
}

// How long the pairing's words still count, the same count keyward's window
// shows. Once it runs out the words mean nothing: try again for new ones.
let ticking = null;
function countdown() {
  const el = $("notice-timer");
  const until = flow.unpaired?.expires || 0;
  if (ticking) clearInterval(ticking);
  ticking = null;
  el.hidden = !until;
  if (!until) return;
  const tick = () => {
    const left = Math.max(0, Math.round(until - Date.now() / 1000));
    el.textContent = left > 0 ? t("pairLeft", [`${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`]) : t("pairExpired");
    el.classList.toggle("expired", left === 0);
    if (left === 0 && ticking) {
      clearInterval(ticking);
      ticking = null;
    }
  };
  tick();
  ticking = setInterval(tick, 1000);
}

function render() {
  const site = host();
  $("site").textContent = site;
  // Nothing of keyward's fits this sign-in.
  const none = flow.kind === "get" && !flow.locked && flow.offers.length === 0;
  $("notice").hidden = !flow.locked && !none;
  $("notice-title").textContent = flow.unpaired ? t("unpairedTitle") : none ? t("noneTitle", [site]) : t("lockedTitle");
  $("notice-text").textContent = flow.unpaired ? t("unpairedText") : none ? t("noneText") : t("lockedText");
  // The key's five words, big and apart: what the person compares with
  // keyward's window.
  const words = $("notice-words");
  words.replaceChildren(
    ...(flow.unpaired?.words ?? []).map((w) => {
      const el = document.createElement("code");
      el.textContent = w;
      return el;
    }),
  );
  words.hidden = !flow.unpaired?.words?.length;
  countdown();
  $("other").textContent = t("otherWay");
  showError("");
  const list = $("choices");
  list.replaceChildren();

  if (flow.kind === "get") {
    document.title = t("signInTitle");
    $("title").textContent = t("signInTitle");
    $("lead").textContent = t("signInLead", [site]);
    for (const o of flow.offers) {
      const user = o.user_name || o.user_display_name || t("noUser");
      list.append(row(`${o.entry_id}\n${o.credential_id}`, user, o.entry_name));
    }
  } else {
    const r = flow.request;
    const user = r.user_name || r.user_display_name;
    document.title = t("createTitle");
    $("title").textContent = t("createTitle");
    $("lead").textContent = user ? t("createLeadUser", [user, site]) : t("createLead", [site]);
    for (const h of flow.homes) {
      list.append(row(h.entry_id, h.entry_name, h.user_name || t("noUser"), { chip: h.has_passkey ? t("replaces") : null }));
    }
    list.append(row("new", t("newLogin"), r.rp_name || site, { fresh: true }));
  }

  const first =
    flow.kind === "create"
      ? (flow.homes.find((h) => !h.has_passkey && h.user_name && h.user_name === flow.request.user_name)?.entry_id ?? "new")
      : list.firstElementChild?.dataset.key;
  if (first) pick(first);
  list.hidden = flow.locked || none;
  setBusy(false);
  $("go").textContent = flow.locked ? t("tryAgain") : flow.kind === "get" ? t("signIn") : t("save");
  // One main action: with nothing to offer, it is the browser's own way.
  $("go").hidden = none;
  $("other").classList.toggle("primary", none);
}

async function retry() {
  const sign_in = { origin: flow.origin, rp_id: flow.request.rp_id, challenge: flow.request.challenge };
  const lookup =
    flow.kind === "get"
      ? await native({ op: "offers", sign_in: { ...sign_in, allow_credentials: flow.request.allow_credentials } })
      : await native({ op: "homes", sign_in });
  if (!lookup.ok) {
    showError(lookup.error);
    return;
  }
  flow.locked = false;
  flow.unpaired = null;
  flow.offers = lookup.offers || [];
  flow.homes = lookup.homes || [];
  await chrome.storage.session.set({ [FLOW + flow.id]: flow });
  render();
}

async function go() {
  if (busy) return;
  if (flow.locked)
    return retry().catch((e) => {
      console.error("keyward: the bridge did not answer", e);
      showError(t("noKeyward"));
    });
  if (!choice) return;
  setBusy(true);
  showError("");
  const r = flow.request;
  let answer;
  try {
    if (flow.kind === "get") {
      const [entry_id, credential_id] = choice.split("\n");
      answer = await native({
        op: "sign_in",
        request: {
          origin: flow.origin,
          rp_id: r.rp_id,
          challenge: r.challenge,
          allow_credentials: r.allow_credentials,
          entry_id,
          credential_id,
        },
      });
      if (answer.ok) return finish({ signed: answer.signed });
    } else {
      const target =
        choice === "new"
          ? { kind: "new", name: r.rp_name || host(), uri: flow.origin }
          : { kind: "existing", entry_id: choice };
      answer = await native({ op: "register", request: { ...r, origin: flow.origin, target } });
      if (answer.ok) return finish({ registered: answer.registered });
      if (answer.code === "err.passkeyExists") return finish({ error: "InvalidStateError" });
      if (answer.code === "err.passkeyAlgorithm") return finish({ error: "NotSupportedError" });
    }
  } catch (e) {
    console.error("keyward: the bridge did not answer", e);
    answer = { error: t("noKeyward") };
  }
  setBusy(false);
  if (answer.code === "err.vaultLocked") {
    flow.locked = true;
    render();
    return;
  }
  showError(answer.error || t("noKeyward"));
}

async function start() {
  const stored = await chrome.storage.session.get(FLOW + flowId);
  flow = stored[FLOW + flowId];
  if (!flow) return window.close();
  $("go").addEventListener("click", go);
  $("other").addEventListener("click", () => !busy && finish({ fallback: true }));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.isComposing) go();
    if (e.key === "Escape" && !busy) finish({ error: "NotAllowedError" });
  });
  render();
  $("go").focus();
}

start();
