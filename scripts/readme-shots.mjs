// The README's screenshots, made from the stand rather than from a real
// vault: node scripts/readme-shots.mjs [name ...]
//
// It starts the stand (ui/stand under vite) and headless WebKit through
// playwright-core, opens each line of the window — the vault's home, an item,
// the map, a verb's preview, a settings section, a plugin's screen, the gate —
// and captures it at 1440×900 (2× pixels), dark theme, English. The page's
// clock stands at the demo's 2026-10-05T12:00:05Z, as in scripts/ui-check.mjs,
// so a one-time code and a "two days ago" read the same in every shot.
// Everything on them is the stand's made-up data: no real account, company,
// host or project name.
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { webkit } from "playwright-core";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const OUT = path.join(ROOT, "docs/assets/shots");
const SIZE = { width: 1440, height: 900 };

// A port nobody holds right now.
const PORT = await new Promise((resolve, reject) => {
  const s = net.createServer();
  s.once("error", reject);
  s.listen(0, "127.0.0.1", () => {
    const { port } = s.address();
    s.close(() => resolve(port));
  });
});
const BASE = `http://127.0.0.1:${PORT}`;

const vite = spawn("npx", ["vite", "--port", String(PORT), "--strictPort", "--host", "127.0.0.1"], { cwd: path.join(ROOT, "ui/stand"), stdio: "ignore", detached: true });
// npx and vite under it are one process group; stopping the group stops both.
const stopVite = () => {
  if (viteExit !== null) return;
  try {
    process.kill(-vite.pid, "SIGTERM");
  } catch (e) {
    if (e.code !== "ESRCH") throw e;
  }
};
process.once("exit", stopVite);
let viteExit = null;
vite.once("exit", (code) => (viteExit = code ?? "signal"));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
for (let i = 0; ; i++) {
  if (viteExit !== null) throw new Error(`the stand's vite exited (${viteExit})`);
  if (await fetch(`${BASE}/`).then((r) => r.ok, () => false)) break;
  if (i > 240) throw new Error("the stand did not come up in 60s");
  await sleep(250);
}

// Pins Date before any of the page's scripts run; timers are untouched.
const CLOCK_JS = `(() => {
  const pinned = Date.UTC(2026, 9, 5, 12, 0, 5);
  const RealDate = Date;
  const now = () => pinned;
  globalThis.Date = new Proxy(RealDate, {
    construct: (t, a, nt) => Reflect.construct(t, a.length ? a : [now()], nt),
    apply: () => new RealDate(now()).toString(),
    get: (t, k, r) => (k === "now" ? now : Reflect.get(t, k, r)),
  });
})()`;

// Waits for the stand's idle signal, the fonts, a quiet DOM and the end of
// every finite animation; infinite ones are frozen at their start, and the
// caret is hidden.
const SETTLE_JS = async () => {
  const t0 = performance.now();
  while (!window.__kwReady) {
    if (performance.now() - t0 > 10000) throw new Error("the stand never set window.__kwReady");
    await new Promise((r) => setTimeout(r, 25));
  }
  await document.fonts.ready;
  let last = performance.now();
  const mo = new MutationObserver(() => (last = performance.now()));
  mo.observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
  for (;;) {
    const running = document.getAnimations().filter((a) => a.playState === "running" && Number.isFinite(a.effect?.getComputedTiming().endTime));
    if (running.length === 0 && performance.now() - last >= 400) break;
    if (performance.now() - t0 > 15000) {
      mo.disconnect();
      throw new Error(`the page did not settle in 15s (${running.length} animations running)`);
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  mo.disconnect();
  for (const a of document.getAnimations()) if (a.effect?.getComputedTiming().endTime === Infinity) { a.pause(); a.currentTime = 0; }
  if (!document.getElementById("kw-shots")) {
    const st = document.createElement("style");
    st.id = "kw-shots";
    st.textContent = "*, *::before, *::after { caret-color: transparent !important; }";
    document.head.append(st);
  }
  await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
};

// Each shot is a stand URL — a line (?q=), a preset (?p=) or a demo flag —
// and, for some, what a person then does on it.
const SHOTS = {
  "vault-home": "q=",
  "login-item": "q=" + encodeURIComponent("acme › acme-collections › platform › github-open-source"),
  "verb-rotate": "q=" + encodeURIComponent("acme › acme-collections › platform › github-open-source > rotate"),
  "access-map": "p=map-acme",
  "org-members": "q=" + encodeURIComponent("acme › acme-members › dana-whitfield"),
  "settings-unlocking": "q=" + encodeURIComponent("settings › settings-unlock"),
  "settings-plugins": "p=plugins",
  "kubernetes-pods": ["p=kube", (page) => page.getByRole("button", { name: "Open", exact: true }).click()],
  "ssh-host": "p=ssh",
  locked: "locked=1",
};

const only = process.argv.slice(2);
for (const name of only) if (!(name in SHOTS)) throw new Error(`no shot "${name}"; there are: ${Object.keys(SHOTS).join(", ")}`);

const browser = await webkit.launch();
let failed = 0;
try {
  for (const [name, shot] of Object.entries(SHOTS)) {
    if (only.length && !only.includes(name)) continue;
    const [query, then] = Array.isArray(shot) ? shot : [shot, null];
    const context = await browser.newContext({ viewport: SIZE, deviceScaleFactor: 2, colorScheme: "dark", locale: "en-US" });
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
    try {
      await page.addInitScript(CLOCK_JS);
      await page.goto(`${BASE}/?lang=en&${query}`, { waitUntil: "load" });
      await page.evaluate(SETTLE_JS);
      if (then) {
        await then(page);
        await page.evaluate(SETTLE_JS);
      }
      // Views that measured text before the web fonts came (the map's fit)
      // measure again after a 1px nudge of the viewport.
      await page.setViewportSize({ width: SIZE.width - 1, height: SIZE.height });
      await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      await page.setViewportSize(SIZE);
      await page.evaluate(SETTLE_JS);
      if (errors.length) throw new Error(`the page reported: ${errors.join(" | ")}`);
      await page.screenshot({ path: path.join(OUT, `${name}.png`) });
      console.log(`docs/assets/shots/${name}.png`);
    } catch (e) {
      failed++;
      console.error(`${name}: ${e.message}`);
    } finally {
      await context.close();
    }
  }
} finally {
  await browser.close();
  stopVite();
}
process.exit(failed ? 1 : 0);
