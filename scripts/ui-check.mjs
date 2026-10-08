// The UI check: a visual and layout regression run over the core's stand
// (ui/stand, Vite dev on :5190). For every preset × theme × size it takes a
// screenshot in headless WebKit (playwright-core), runs the layout audit (scripts/stand-audit.js,
// scoped to the core's kw- containers) and the alignment probe
// (scripts/stand-align.js), and collects console errors.
//
//   node scripts/ui-check.mjs            compare with ui/stand/baselines/
//   node scripts/ui-check.mjs --update   write the baselines (clean runs only)
//
// Options: --only=aws,map-ssh  --themes=dark,light  --sizes=1440x900,1280x800
//          --threshold=0.001 (share of changed pixels allowed)
//          --tolerance=8 (per-channel delta below which a pixel is unchanged)
//          --jobs=3 (WebKits in the pool)  --out=<dir>  --url=http://localhost:5190
//          --baselines=<dir> (default ui/stand/baselines)
//          --strict (a flaky run, one that matched only on a second capture, fails)
//
// The page's clock is pinned (Date stands at the demo's 2026-10-05T12:00:05Z),
// so time-based codes, countdowns and "synced" labels repeat. A
// page that reloads under the run (Vite's HMR when a source changes) or a
// WebKit that hangs is retried once, on a fresh one. The run starts with a
// warm-up load so Vite has transformed the modules. --update writes a baseline
// only when two captures agree; a normal run captures a visual mismatch once
// more and reports it "flaky" when the second capture matches.
//
// A run fails (exit 1) on any pixel diff over the threshold, any audit or
// alignment finding, a change of the type/padding inventory against the
// baseline, a console error, or a run that could not finish. Bad usage or a
// stand that is not up exits 2. Diff images, the current shots of what
// changed and report.json go to the output directory.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { webkit } from "playwright-core";
import { decodePng, encodePng } from "./png.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

const PRESETS = ["home", "aws", "acme", "dana", "finance", "ssh", "critical", "critical-step", "rotate", "map-aws", "map-acme", "map-ssh", "typing", "en", "locked"];
// A preset is the stand's ?p=; "locked" is the gate (?locked=1, with the
// desktop's other accounts beside it) instead.
const query = (preset) => (preset === "locked" ? "locked=1&accounts=1" : `p=${encodeURIComponent(preset)}`);
const AUDIT_SCOPE = ".kw-window, .kw-gate";
// The audit's real findings; its pads and type lists are inventories, compared
// with the baseline instead of being required to be empty.
const AUDIT_FINDINGS = ["spill", "grid", "cramped", "edges", "tabs", "head"];

// ---------------------------------------------------------------- options

const args = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const m = a.match(/^--([a-z]+)(?:=(.*))?$/);
    if (!m) usage(`unknown argument ${a}`);
    return [m[1], m[2] ?? true];
  }),
);
const KNOWN = ["update", "strict", "only", "themes", "sizes", "threshold", "tolerance", "jobs", "out", "url", "baselines"];
for (const k of Object.keys(args)) if (!KNOWN.includes(k)) usage(`unknown option --${k}`);
function usage(why) {
  console.error(`ui-check: ${why}\nusage: node scripts/ui-check.mjs [--update] [--strict] [--only=p1,p2] [--themes=dark,light] [--sizes=WxH,...] [--threshold=0.001] [--tolerance=8] [--jobs=3] [--out=dir] [--url=http://localhost:5190] [--baselines=dir]`);
  process.exit(2);
}
const list = (v, all) => (typeof v === "string" ? v.split(",").map((s) => s.trim()).filter(Boolean) : all);
const UPDATE = args.update === true;
const STRICT = args.strict === true;
const presets = list(args.only, PRESETS);
for (const p of presets) if (!PRESETS.includes(p)) usage(`no preset "${p}"; there are: ${PRESETS.join(", ")}`);
const themes = list(args.themes, ["dark", "light"]);
for (const t of themes) if (!["dark", "light"].includes(t)) usage(`no theme "${t}"`);
const sizes = list(args.sizes, ["1440x900", "1280x800"]).map((s) => {
  const m = s.match(/^(\d+)x(\d+)$/);
  if (!m) usage(`bad size "${s}"`);
  return { name: s, w: +m[1], h: +m[2] };
});
const num = (v, d, name) => {
  if (v === undefined) return d;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) usage(`bad --${name}=${v}`);
  return n;
};
const THRESHOLD = num(args.threshold, 0.001, "threshold");
const TOLERANCE = num(args.tolerance, 8, "tolerance");
const JOBS = Math.max(1, Math.floor(num(args.jobs, 3, "jobs")));
const BASE_URL = (typeof args.url === "string" ? args.url : "http://localhost:5190").replace(/\/$/, "");
const BASELINES = typeof args.baselines === "string" ? args.baselines : join(ROOT, "ui/stand/baselines");
const OUT = typeof args.out === "string" ? args.out : join(tmpdir(), "keyward-ui-check", new Date().toISOString().replace(/[:.]/g, "-"));

const AUDIT_JS = readFileSync(join(HERE, "stand-audit.js"), "utf8");
const ALIGN_JS = readFileSync(join(HERE, "stand-align.js"), "utf8");

// ---------------------------------------------------------------- WebKit

class Hung extends Error {}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** One headless WebKit (playwright-core's build: `npx playwright-core install webkit`). */
class Browser {
  static async launch() {
    try {
      return new Browser(await webkit.launch());
    } catch (e) {
      throw new Hung(`WebKit did not come up: ${e.message.split("\n")[0]}`);
    }
  }

  constructor(browser) {
    this.browser = browser;
    this.dead = false;
    browser.on("disconnected", () => (this.dead = true));
  }

  async kill() {
    this.dead = true;
    await this.browser.close().catch(() => {});
  }
}

// ---------------------------------------------------------------- one run

// Pins the page's clock before any of its scripts run: Date stands still at
// the demo's "now", so a one-time code and its countdown are the same in
// every shot. Timers are untouched (they do not read Date).
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

// Waits in the page for the stand's idle signal, the fonts, a quiet DOM and
// the end of every finite animation; infinite ones are frozen at their start.
const SETTLE_JS = `(async () => {
  const t0 = performance.now();
  const frame = () => new Promise((r) => requestAnimationFrame(() => r()));
  while (!window.__kwReady) {
    if (performance.now() - t0 > 10000) return { ok: false, why: "the stand never set window.__kwReady" };
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
      return { ok: false, why: "the page did not settle in 15s (" + running.length + " animations running)" };
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  mo.disconnect();
  for (const a of document.getAnimations()) if (a.effect?.getComputedTiming().endTime === Infinity) { a.pause(); a.currentTime = 0; }
  if (!document.getElementById("kw-ui-check")) {
    const st = document.createElement("style");
    st.id = "kw-ui-check";
    st.textContent = "*, *::before, *::after { caret-color: transparent !important; }";
    document.head.append(st);
  }
  await frame();
  await frame();
  return { ok: true, ms: Math.round(performance.now() - t0) };
})()`;

// The page went away under the run: Vite reloaded it after a source changed;
// or the browser is gone.
const RELOADED = /navigated|Execution context was destroyed|Target (page, context or browser )?(has been )?closed|Browser has been closed/;

async function evaluate(page, expression, timeout) {
  try {
    return await Promise.race([page.evaluate(expression), sleep(timeout ?? 15000).then(() => Promise.reject(new Hung(`the page did not answer in ${timeout ?? 15000}ms`)))]);
  } catch (e) {
    if (e instanceof Hung) throw e;
    if (RELOADED.test(e.message)) throw new Hung(`the page reloaded under the run (${e.message.split("\n")[0]})`);
    throw new Error(`in the page: ${e.message.split("\n")[0]}`);
  }
}

async function capture(browser, job) {
  const consoleErrors = [];
  const warnings = [];
  const ctx = await browser.browser.newContext({ viewport: { width: job.size.w, height: job.size.h }, deviceScaleFactor: 1, colorScheme: job.theme });
  try {
    await ctx.addInitScript(CLOCK_JS);
    const page = await ctx.newPage();
    page.on("console", (m) => {
      // The browser asks for /favicon.ico by itself; the stand has none, and
      // that is the browser's request, not the page's.
      if (/\/favicon\.ico$/.test(m.location().url ?? "")) return;
      if (m.type() === "error" || m.type() === "assert") consoleErrors.push(m.text());
      else if (m.type() === "warning") warnings.push(m.text());
    });
    page.on("pageerror", (e) => consoleErrors.push("uncaught " + e.message));
    try {
      await page.goto(job.url, { waitUntil: "load", timeout: 20000 });
    } catch (e) {
      throw new Hung(`no load in 20s (${e.message.split("\n")[0]})`);
    }
    const first = await evaluate(page, SETTLE_JS, 30000);
    if (!first.ok) return { error: first.why, consoleErrors, warnings };
    // The web fonts (fontsource) arrive after the first render; a view that
    // measured text before them (the map's fit) keeps those numbers until
    // its size changes. A 1px nudge of the viewport makes every measured view
    // measure again, now with the fonts, so the shot does not depend on how
    // fast the fonts came.
    await page.setViewportSize({ width: job.size.w - 1, height: job.size.h });
    await evaluate(page, "new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => r(1))))");
    await page.setViewportSize({ width: job.size.w, height: job.size.h });
    const settled = await evaluate(page, SETTLE_JS, 30000);
    if (!settled.ok) return { error: settled.why, consoleErrors, warnings };
    settled.ms += first.ms;
    const png = await page.screenshot({ type: "png" });
    await evaluate(page, `(window.__kwAuditScope = ${JSON.stringify(AUDIT_SCOPE)}, 1)`);
    const audit = await evaluate(page, AUDIT_JS);
    const align = await evaluate(page, ALIGN_JS);
    return { png, audit, align, settleMs: settled.ms, consoleErrors, warnings };
  } finally {
    await ctx.close().catch(() => {});
  }
}

// ---------------------------------------------------------------- comparing

function pixelDiff(basePng, curPng) {
  const a = decodePng(basePng);
  const b = decodePng(curPng);
  if (a.width !== b.width || a.height !== b.height) return { sizeMismatch: `${a.width}x${a.height} → ${b.width}x${b.height}`, ratio: 1 };
  const n = a.width * a.height;
  const img = new Uint8Array(n * 4);
  let changed = 0, maxDelta = 0;
  let x0 = Infinity, y0 = Infinity, x1 = -1, y1 = -1;
  for (let i = 0; i < n; i++) {
    const o = i * 4;
    const d = Math.max(Math.abs(a.data[o] - b.data[o]), Math.abs(a.data[o + 1] - b.data[o + 1]), Math.abs(a.data[o + 2] - b.data[o + 2]), Math.abs(a.data[o + 3] - b.data[o + 3]));
    if (d > maxDelta) maxDelta = d;
    if (d > TOLERANCE) {
      changed++;
      const x = i % a.width, y = (i / a.width) | 0;
      if (x < x0) x0 = x;
      if (y < y0) y0 = y;
      if (x > x1) x1 = x;
      if (y > y1) y1 = y;
      img[o] = 255; img[o + 1] = 0; img[o + 2] = 64; img[o + 3] = 255;
    } else {
      // The baseline, greyed and faded, so the changed pixels stand out.
      const l = (a.data[o] * 0.3 + a.data[o + 1] * 0.59 + a.data[o + 2] * 0.11) * 0.35 + 90;
      img[o] = img[o + 1] = img[o + 2] = l; img[o + 3] = 255;
    }
  }
  return {
    ratio: changed / n,
    changed,
    maxDelta,
    box: changed ? { x: x0, y: y0, w: x1 - x0 + 1, h: y1 - y0 + 1 } : null,
    image: changed ? encodePng({ width: a.width, height: a.height, data: img }) : null,
  };
}

const findingsOf = (r) => ({
  audit: Object.fromEntries(AUDIT_FINDINGS.map((k) => [k, r.audit?.[k] ?? []]).filter(([, v]) => v.length)),
  align: r.align?.issues ?? [],
});

function inventoryDrift(base, cur) {
  const out = [];
  for (const k of ["pads", "type"]) {
    const a = new Set(base[k] ?? []), b = new Set(cur[k] ?? []);
    for (const x of b) if (!a.has(x)) out.push(`${k} + ${x}`);
    for (const x of a) if (!b.has(x)) out.push(`${k} - ${x}`);
  }
  return out;
}

// ---------------------------------------------------------------- the run

async function standIsUp() {
  try {
    const r = await fetch(BASE_URL + "/", { signal: AbortSignal.timeout(3000) });
    return r.ok;
  } catch {
    return false;
  }
}

if (!existsSync(webkit.executablePath())) {
  console.error(`ui-check: no WebKit at ${webkit.executablePath()}; get it with: npx playwright-core install webkit`);
  process.exit(2);
}
if (!(await standIsUp())) {
  console.error(`ui-check: the stand does not answer at ${BASE_URL}; start it with: npm -w @keyward/stand run dev`);
  process.exit(2);
}
mkdirSync(OUT, { recursive: true });
if (UPDATE) mkdirSync(BASELINES, { recursive: true });

const jobs = [];
for (const preset of presets)
  for (const theme of themes)
    for (const size of sizes) jobs.push({ preset, theme, size, name: `${preset}-${theme}-${size.name}`, url: `${BASE_URL}/?${query(preset)}` });

const JOB_TIMEOUT = 60000;
const results = [];
const t0 = Date.now();

const metricsOf = (job, r) => ({ url: job.url, layout: r.align?.layout ?? null, pads: r.audit?.pads ?? [], type: r.audit?.type ?? [], findings: findingsOf(r), consoleErrors: r.consoleErrors });

// What is wrong with a capture by itself: it did not finish, the audit or the
// probe found something, or the console has errors.
function ownProblems(r) {
  if (r.error) return [r.error, ...(r.consoleErrors ?? []).map((e) => "console: " + e)];
  const f = findingsOf(r);
  const out = [];
  for (const [k, v] of Object.entries(f.audit)) for (const x of v) out.push(`audit ${k}: ${x}`);
  for (const x of f.align) out.push(`align: ${x}`);
  for (const e of r.consoleErrors) out.push(`console: ${e}`);
  return out;
}

// What differs between a capture and a reference (the baseline, or another
// capture of the same run): the probe's layout, the type/padding inventory,
// the pixels.
function visualProblems(refPng, refMetrics, r, metrics) {
  const out = [];
  if (refMetrics.layout !== metrics.layout) out.push(`layout ${refMetrics.layout} → ${metrics.layout}`);
  for (const d of inventoryDrift(refMetrics, metrics)) out.push(`inventory ${d}`);
  const d = pixelDiff(refPng, r.png);
  if (d.sizeMismatch) out.push(`screenshot size ${d.sizeMismatch}`);
  else if (d.ratio > THRESHOLD) out.push(`pixels: ${(d.ratio * 100).toFixed(3)}% changed (${d.changed} px, max delta ${d.maxDelta}, box ${d.box.x},${d.box.y} ${d.box.w}x${d.box.h})`);
  return { problems: out, diff: d };
}

/** One capture of a job, with a hung WebKit replaced and the capture retried once. */
async function attempt(state, job) {
  for (let tries = 1; ; tries++) {
    try {
      if (!state.chrome || state.chrome.dead) state.chrome = await Browser.launch();
      let timer;
      const r = await Promise.race([
        capture(state.chrome, job),
        new Promise((_, rej) => (timer = setTimeout(() => rej(new Hung(`no result in ${JOB_TIMEOUT / 1000}s`)), JOB_TIMEOUT))),
      ]).finally(() => clearTimeout(timer));
      return { ...r, tries };
    } catch (e) {
      if (!(e instanceof Hung)) return { error: `failed: ${e.message}`, tries };
      await state.chrome?.kill();
      state.chrome = null;
      if (tries >= 2) return { error: `failed twice: ${e.message}`, tries };
      process.stderr.write(`  ${job.name}: ${e.message}; retrying on a fresh WebKit\n`);
    }
  }
}

const rowOf = (job, r) => ({
  name: job.name, preset: job.preset, theme: job.theme, size: job.size.name, problems: [], flaky: null, diff: null,
  audit: r.error ? null : Object.values(findingsOf(r).audit).reduce((s, v) => s + v.length, 0),
  align: r.error ? null : findingsOf(r).align.length,
  console: r.consoleErrors?.length ?? null,
  warnings: r.warnings?.length ?? null,
  captures: 1,
  retried: (r.tries ?? 1) > 1,
});

// --update: a baseline is written only from a clean capture that a second
// capture repeats; if the two differ, a third decides, and with no two alike
// the job is unstable and nothing is written.
async function updateJob(state, job) {
  const caps = [await attempt(state, job)];
  const row = rowOf(job, caps[0]);
  row.problems = ownProblems(caps[0]);
  if (row.problems.length) {
    if (caps[0].png) writeFileSync(join(OUT, job.name + ".png"), caps[0].png);
    return (row.problems.unshift("baseline NOT written"), row);
  }
  const same = (a, b) => visualProblems(a.png, metricsOf(job, a), b, metricsOf(job, b)).problems.length === 0;
  caps.push(await attempt(state, job));
  let pick = !caps[1].error && same(caps[0], caps[1]) ? caps[0] : null;
  if (!pick) {
    caps.push(await attempt(state, job));
    const [a, b, c] = caps;
    pick = !c.error && same(a, c) ? a : !c.error && !b.error && same(b, c) ? b : null;
    row.flaky = "the first two captures differed";
  }
  row.captures = caps.length;
  if (!pick) return (row.problems.push("baseline NOT written: three captures, no two alike (unstable render)"), row);
  const own = ownProblems(pick);
  if (own.length) return (row.problems.push("baseline NOT written", ...own), row);
  writeFileSync(join(BASELINES, job.name + ".png"), pick.png);
  writeFileSync(join(BASELINES, job.name + ".json"), JSON.stringify(metricsOf(job, pick), null, 2) + "\n");
  return row;
}

// A normal run: a capture is compared with its baseline; a visual mismatch is
// captured once more, and passes as "flaky" (reported, failing only under
// --strict) when the second capture matches.
async function checkJob(state, job) {
  const pngPath = join(BASELINES, job.name + ".png");
  const jsonPath = join(BASELINES, job.name + ".json");
  let r = await attempt(state, job);
  const row = rowOf(job, r);
  row.problems = ownProblems(r);
  if (r.error) return row;
  if (!existsSync(pngPath) || !existsSync(jsonPath)) {
    row.problems.push("no baseline; run with --update");
    writeFileSync(join(OUT, job.name + ".png"), r.png);
    return row;
  }
  const basePng = readFileSync(pngPath);
  const base = JSON.parse(readFileSync(jsonPath, "utf8"));
  let v = visualProblems(basePng, base, r, metricsOf(job, r));
  if (v.problems.length && !row.problems.length) {
    const again = await attempt(state, job);
    row.captures = 2;
    if (!again.error && ownProblems(again).length === 0) {
      const v2 = visualProblems(basePng, base, again, metricsOf(job, again));
      if (v2.problems.length === 0) {
        row.flaky = v.problems.join("; ");
        if (v.diff.image) writeFileSync(join(OUT, job.name + ".flaky.diff.png"), v.diff.image);
        writeFileSync(join(OUT, job.name + ".flaky.png"), r.png);
        r = again;
        v = v2;
      }
    }
  }
  row.problems.push(...v.problems);
  if (STRICT && row.flaky) row.problems.push(`flaky: ${row.flaky}`);
  row.diff = v.diff.ratio;
  if (v.diff.image) writeFileSync(join(OUT, job.name + ".diff.png"), v.diff.image);
  if (row.problems.length) writeFileSync(join(OUT, job.name + ".png"), r.png);
  return row;
}

// Vite transforms the stand's modules on their first request; a page loaded
// while that is still going can lay out differently, so the run starts warm.
async function warmUp() {
  const state = { chrome: null };
  try {
    for (const preset of ["home", "map-ssh"]) {
      const r = await attempt(state, { name: `warm-up ${preset}`, preset, theme: "dark", size: sizes[0], url: `${BASE_URL}/?${query(preset)}` });
      if (r.error) throw new Error(`warm-up on ${preset} failed: ${r.error}`);
    }
  } finally {
    await state.chrome?.kill();
  }
}

async function worker() {
  const state = { chrome: null };
  try {
    for (;;) {
      const job = jobs.shift();
      if (!job) return;
      const started = Date.now();
      const row = await (UPDATE ? updateJob : checkJob)(state, job);
      row.ms = Date.now() - started;
      results.push(row);
      process.stderr.write(`${row.problems.length ? "FAIL " : row.flaky ? "flaky" : " ok  "} ${job.name} ${row.ms}ms\n`);
    }
  } finally {
    await state.chrome?.kill();
  }
}

try {
  await warmUp();
} catch (e) {
  console.error(`ui-check: ${e.message}`);
  process.exit(2);
}
const warmMs = Date.now() - t0;
await Promise.all(Array.from({ length: Math.min(JOBS, jobs.length) }, worker));
const wall = Date.now() - t0;

// ---------------------------------------------------------------- report

results.sort((a, b) => a.name.localeCompare(b.name));
const pad = (s, n) => String(s).padEnd(n);
const lpad = (s, n) => String(s).padStart(n);
const q = (v) => (v === null || v === undefined ? "?" : v);
console.log(`\n${pad("run", 34)}${lpad("pixels", 9)}${lpad("audit", 7)}${lpad("align", 7)}${lpad("console", 9)}${lpad("ms", 7)}  status`);
for (const r of results) {
  const px = UPDATE ? "-" : r.diff === null ? "?" : (r.diff * 100).toFixed(3) + "%";
  const status = r.problems.length ? "FAIL" : r.flaky ? (UPDATE ? "written (flaky)" : "flaky") : UPDATE ? "written" : "ok";
  console.log(`${pad(r.name, 34)}${lpad(px, 9)}${lpad(q(r.audit), 7)}${lpad(q(r.align), 7)}${lpad(q(r.console), 9)}${lpad(r.ms, 7)}  ${status}${r.retried ? " (WebKit retried)" : ""}`);
}
const failed = results.filter((r) => r.problems.length);
const flaky = results.filter((r) => !r.problems.length && r.flaky);
// One line a problem here (a stack is cut to its message); report.json has it all.
const short = (p) => (p.split("\n")[0] ?? "").slice(0, 240);
for (const r of failed) console.log(`\n${r.name}:\n  ` + r.problems.slice(0, 20).map(short).join("\n  ") + (r.problems.length > 20 ? `\n  … ${r.problems.length - 20} more` : ""));
for (const r of flaky) console.log(`\n${r.name} (flaky):\n  ${short(r.flaky)}`);
const total = results.reduce((s, r) => s + r.ms, 0);
writeFileSync(join(OUT, "report.json"), JSON.stringify({ update: UPDATE, strict: STRICT, threshold: THRESHOLD, tolerance: TOLERANCE, wallMs: wall, warmUpMs: warmMs, results }, null, 2) + "\n");
console.log(
  `\n${results.length} runs, ${failed.length} failed, ${flaky.length} flaky; wall ${(wall / 1000).toFixed(1)}s with ${JOBS} WebKits ` +
    `(warm-up ${(warmMs / 1000).toFixed(1)}s, ${(total / results.length / 1000).toFixed(2)}s a run); ${UPDATE ? `baselines in ${BASELINES}; ` : ""}output in ${OUT}`,
);
process.exit(failed.length ? 1 : 0);
