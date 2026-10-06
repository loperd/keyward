// Screenshots of the stand, driven through a headless Chrome over its
// DevTools protocol: no browser automation package, Node's own WebSocket.
//
//   node scripts/stand-shot.mjs <url> <WxH> '<steps json>'
//
// steps: {shot:"name"} | {click:"css", after?:ms} | {clickText:"text"} | {wait:ms} | {eval:"js"}
//        | {audit:"label"} — runs scripts/stand-audit.js in the page and prints its findings
// OUT=<dir> picks where the pictures go (default: the system's temp dir);
// SCHEME=light|dark emulates the system's colour scheme.
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [url, size, stepsJson] = process.argv.slice(2);
if (!url || !size || !stepsJson) {
  console.error("usage: node scripts/stand-shot.mjs <url> <WxH> '<steps json>'");
  process.exit(2);
}
const steps = JSON.parse(stepsJson);
const [w, h] = size.split("x").map(Number);
const out = process.env.OUT ?? join(tmpdir(), "keyward-shots");
mkdirSync(out, { recursive: true });
const port = 9300 + Math.floor(Math.random() * 500);
const profile = mkdtempSync(join(tmpdir(), "kwcdp-"));
const chrome = spawn(
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ["--headless=new", "--disable-gpu", "--hide-scrollbars", `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, `--window-size=${w},${h}`, "about:blank"],
  { stdio: "ignore" },
);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let target;
for (let i = 0; i < 200 && !target; i++) {
  try {
    target = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find((t) => t.type === "page");
  } catch {
    /* Chrome is still starting */
  }
  if (!target) await sleep(100);
}
if (!target) {
  chrome.kill();
  throw new Error("Chrome did not come up");
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
let id = 0;
const pending = new Map();
const logs = [];
ws.addEventListener("message", (e) => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m);
    pending.delete(m.id);
  }
  if (m.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(m.params.type)) logs.push(m.params.args.map((a) => a.value ?? a.description).join(" "));
  if (m.method === "Runtime.exceptionThrown") logs.push("EXC " + m.params.exceptionDetails.exception?.description);
});
const send = (method, params = {}) =>
  new Promise((r) => {
    const i = ++id;
    pending.set(i, r);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
const evaluate = async (expr) => (await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })).result?.result?.value;
await send("Runtime.enable");
await send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile: false });
if (process.env.SCHEME) await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: process.env.SCHEME }] });
await send("Page.enable");
await send("Page.navigate", { url });
await sleep(2500);
for (const s of steps) {
  if (s.wait) await sleep(s.wait);
  if (s.click) {
    const ok = await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(s.click)}); if(!e) return false; e.click(); return true})()`);
    if (!ok) logs.push("no element " + s.click);
    await sleep(s.after ?? 700);
  }
  if (s.clickText) {
    const ok = await evaluate(
      `(()=>{const t=${JSON.stringify(s.clickText)}; const els=[...document.querySelectorAll('button,a,[role=button],[role=tab]')].filter(e=>(e.textContent||'').trim().includes(t)||(e.getAttribute('title')||'')===t); const e=els[els.length-1]; if(!e) return false; e.click(); return true})()`,
    );
    if (!ok) logs.push("no text " + s.clickText);
    await sleep(s.after ?? 700);
  }
  if (s.eval) console.log("eval:", JSON.stringify(await evaluate(s.eval)));
  if (s.audit) {
    const found = await evaluate(readFileSync(new URL("./stand-audit.js", import.meta.url), "utf8"));
    console.log(`== audit: ${s.audit}`);
    for (const [k, v] of Object.entries(found ?? {})) if (v.length) console.log(`  ${k} (${v.length}):\n    ` + v.slice(0, 25).join("\n    "));
  }
  if (s.shot) {
    const r = await send("Page.captureScreenshot", { format: "png" });
    const file = join(out, s.shot + ".png");
    writeFileSync(file, Buffer.from(r.result.data, "base64"));
    console.log(file);
  }
}
if (logs.length) console.log("console:\n" + logs.join("\n"));
ws.close();
chrome.kill();
