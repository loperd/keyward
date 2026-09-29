// The Chrome Web Store's pictures, made from the real chooser rather than
// drawn by hand: node scripts/extension-store-assets.mjs
//
// The chooser (extension/chromium/chooser.html) is rendered in headless Chrome
// with the extension's APIs stubbed and made-up data — no real account, site
// or item names — and set into extension/store/compose.html at the sizes the
// store takes: two 1280×800 screenshots and a 440×280 promo tile, dark
// graphite and sea turquoise, as the app is.
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const EXT = path.join(ROOT, "extension");
const OUT = path.join(EXT, "store");
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "kw-assets-"));
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".png": "image/png", ".json": "application/json", ".woff2": "font/woff2" };
const server = http.createServer((req, res) => {
  const url = decodeURIComponent(new URL(req.url, "http://x").pathname);
  const file = url.startsWith("/tmp-assets/") ? path.join(TMP, url.slice(12)) : path.join(EXT, url);
  if (!file.startsWith(EXT) && !file.startsWith(TMP)) return res.writeHead(403).end();
  fs.readFile(file, (err, data) => {
    if (err) return res.writeHead(404).end();
    res.writeHead(200, { "content-type": TYPES[path.extname(file)] || "application/octet-stream", "cache-control": "no-store" }).end(data);
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const port = 9400 + Math.floor(Math.random() * 400);
const chrome = spawn(CHROME, ["--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions", "--hide-scrollbars", `--user-data-dir=${path.join(TMP, "profile")}`, `--remote-debugging-port=${port}`, "about:blank"], { stdio: "ignore" });
let pages;
for (let i = 0; i < 60 && !pages; i++) {
  await new Promise((r) => setTimeout(r, 250));
  pages = await fetch(`http://127.0.0.1:${port}/json/list`).then((r) => r.json()).catch(() => null);
}
if (!pages) throw new Error("headless Chrome did not come up");
const ws = new WebSocket(pages.find((t) => t.type === "page").webSocketDebuggerUrl);
let n = 0;
const waiting = new Map();
const send = (method, params = {}) => new Promise((r) => { const id = ++n; waiting.set(id, r); ws.send(JSON.stringify({ id, method, params })); });
ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } };
await new Promise((r) => (ws.onopen = r));
await send("Page.enable");
await send("Network.enable");
await send("Network.setCacheDisabled", { cacheDisabled: true });
await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "dark" }] });

const messages = JSON.parse(fs.readFileSync(path.join(EXT, "chromium/_locales/en/messages.json"), "utf8"));
const flows = {
  get: {
    id: "f", kind: "get", tabId: 1, origin: "https://accounts.example.com", request: {}, locked: false, homes: [],
    offers: [
      { entry_id: "a", entry_name: "Example — personal", credential_id: "x", rp_id: "example.com", user_name: "alex@example.com", discoverable: true },
      { entry_id: "b", entry_name: "Example — work", credential_id: "y", rp_id: "example.com", user_name: "alex@work.example", discoverable: true },
    ],
  },
  create: {
    id: "f", kind: "create", tabId: 1, origin: "https://shop.example.com", locked: false, offers: [],
    request: { rp_name: "Example Shop", user_name: "alex@example.com" },
    homes: [{ entry_id: "h1", entry_name: "Example Shop", user_name: "alex@example.com", has_passkey: false }],
  },
};

let script = null;
async function render(url, width, height, scale, file, flow) {
  if (script) await send("Page.removeScriptToEvaluateOnNewDocument", { identifier: script });
  script = null;
  if (flow) {
    const stub = `window.chrome = { i18n: { getMessage: (k, s) => { const m = ${JSON.stringify(messages)}[k]; if (!m) return ""; let t = m.message; for (const [n, v] of Object.entries(m.placeholders || {})) { const i = Number(v.content.slice(1)) - 1; t = t.replaceAll("$" + n.toUpperCase() + "$", (Array.isArray(s) ? s : [s])[i] ?? ""); } return t; } }, storage: { session: { get: async () => ({ "flow:f": ${JSON.stringify(flow)} }), set: async () => {}, remove: async () => {} } }, tabs: { sendMessage: async () => {} }, runtime: {} };`;
    script = (await send("Page.addScriptToEvaluateOnNewDocument", { source: stub })).result.identifier;
  }
  await send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: scale, mobile: false });
  await send("Page.navigate", { url });
  await new Promise((r) => setTimeout(r, 1500));
  const shot = await send("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(file, Buffer.from(shot.result.data, "base64"));
}

// A query of its own for each: the same address twice would be a jump to the
// same anchor, not a load, and the second flow would never be read.
await render(`${base}/chromium/chooser.html?shot=get#f`, 420, 520, 2, path.join(TMP, "chooser-get.png"), flows.get);
await render(`${base}/chromium/chooser.html?shot=create#f`, 420, 520, 2, path.join(TMP, "chooser-create.png"), flows.create);
await render(`${base}/store/compose.html?kind=sign-in&chooser=/tmp-assets/chooser-get.png`, 1280, 800, 1, path.join(OUT, "screenshot-sign-in.png"));
await render(`${base}/store/compose.html?kind=save&chooser=/tmp-assets/chooser-create.png`, 1280, 800, 1, path.join(OUT, "screenshot-save.png"));
await render(`${base}/store/compose.html?kind=tile`, 440, 280, 1, path.join(OUT, "promo-small.png"));

ws.close();
await new Promise((r) => { chrome.once("exit", r); chrome.kill(); });
server.close();
fs.rmSync(TMP, { recursive: true, force: true });
for (const f of ["screenshot-sign-in.png", "screenshot-save.png", "promo-small.png"]) console.log(path.join(OUT, f));
