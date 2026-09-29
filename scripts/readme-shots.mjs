// The README's screenshots, made from the stand rather than from a real
// vault: node scripts/readme-shots.mjs
//
// It starts the stand (gui/preview.html under vite) and headless Chrome, plays
// each state — a list, a card, a dialogue, a section — and captures it at
// 1440×980, dark theme, English. Everything on them is the stand's made-up
// data: no real account, company, host or project name.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const OUT = path.join(ROOT, "docs/assets/shots");
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "kw-shots-"));
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = 5300 + Math.floor(Math.random() * 300);

const vite = spawn("npx", ["vite", "--port", String(PORT), "--strictPort"], { cwd: path.join(ROOT, "gui"), stdio: "ignore" });
const debug = 9700 + Math.floor(Math.random() * 200);
const chrome = spawn(CHROME, ["--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions", "--hide-scrollbars", `--user-data-dir=${path.join(TMP, "profile")}`, `--remote-debugging-port=${debug}`, "about:blank"], { stdio: "ignore" });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, what) {
  for (let i = 0; i < 120; i++) {
    const v = await fn().catch(() => null);
    if (v) return v;
    await sleep(250);
  }
  throw new Error(`${what} did not come up`);
}
await until(() => fetch(`http://localhost:${PORT}/preview.html`).then((r) => r.ok), "the stand");
const pages = await until(() => fetch(`http://127.0.0.1:${debug}/json/list`).then((r) => r.json()), "headless Chrome");

const ws = new WebSocket(pages.find((t) => t.type === "page").webSocketDebuggerUrl);
let n = 0;
const waiting = new Map();
const send = (method, params = {}) => new Promise((r) => { const id = ++n; waiting.set(id, r); ws.send(JSON.stringify({ id, method, params })); });
ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } };
await new Promise((r) => (ws.onopen = r));
await send("Page.enable");
await send("Network.enable");
await send("Network.setCacheDisabled", { cacheDisabled: true });
await send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 980, deviceScaleFactor: 1, mobile: false });
await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });

const run = async (expression) => {
  const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (r.result?.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || "a step failed");
  return r.result?.result?.value;
};

// Clicks the element a person would: by its accessible name, its title or
// its own text. Fails loudly when it is not there — a shot of the wrong
// state is worse than none.
const click = (label) =>
  run(`(() => {
    const want = ${JSON.stringify(label)};
    const names = (e) => [e.getAttribute("aria-label"), e.getAttribute("title"), e.textContent].map((v) => (v || "").trim()).filter(Boolean);
    const all = [...document.querySelectorAll("button, [role=button], a, .row, li, [role=tab]")];
    // Exact first, then the start, then the narrowest element that contains it
    // (a card's row reads "VISA" before its name).
    const containing = all.filter((e) => names(e).some((v) => v.includes(want))).sort((a, b) => a.textContent.length - b.textContent.length);
    const el = all.find((e) => names(e).includes(want)) || all.find((e) => names(e).some((v) => v.startsWith(want))) || containing[0];
    if (!el) throw new Error("not found: " + want);
    el.click();
    return true;
  })()`);

const key = async (keyName, code, modifiers) => {
  for (const type of ["keyDown", "keyUp"]) await send("Input.dispatchKeyEvent", { type, key: keyName, code, modifiers, windowsVirtualKeyCode: keyName.toUpperCase().charCodeAt(0) });
};

async function open(query = "") {
  await send("Page.navigate", { url: `http://localhost:${PORT}/preview.html?lang=en${query}` });
  await until(() => run(`document.querySelectorAll(".row, .rail-item, .gate").length > 0`), "the stand's screen");
  await sleep(800);
}

async function shot(name) {
  await sleep(700);
  const r = await send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(OUT, `${name}.png`), Buffer.from(r.result.data, "base64"));
  console.log(`docs/assets/shots/${name}.png`);
}

const SHOTS = {
  inventory: async () => { await open(); },
  "filters-open": async () => { await open(); await click("Filters"); },
  "command-palette": async () => { await open(); await key("k", "KeyK", 4); },
  "card-detail": async () => { await open(); await click("Stripe — finance"); },
  "edit-card": async () => { await open(); await click("Stripe — finance"); await sleep(600); await click("Edit"); },
  "new-item": async () => { await open(); await click("New item"); },
  "ssh-key-detail": async () => { await open(); await click("id_ed25519 — production"); },
  "vault-access": async () => { await open(); await click("Vault"); },
  vaultwarden: async () => { await open(); await click("Vaultwarden"); },
  generator: async () => { await open(); await click("Generator"); },
  locked: async () => { await open("&locked=1"); },
  preferences: async () => { await open(); await click("Settings"); await sleep(500); await click("Preferences"); },
  security: async () => { await open(); await click("Settings"); await sleep(500); await click("Security"); },
};

const only = process.argv.slice(2);
let failed = 0;
for (const [name, play] of Object.entries(SHOTS)) {
  if (only.length && !only.includes(name)) continue;
  try {
    await play();
    await shot(name);
  } catch (e) {
    failed++;
    console.error(`${name}: ${e.message}`);
  }
}

ws.close();
await new Promise((r) => { chrome.once("exit", r); chrome.kill(); });
vite.kill();
fs.rmSync(TMP, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
