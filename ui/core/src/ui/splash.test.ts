// The splash before the script cannot read the theme's tokens, so it writes
// the few colours it needs out (splash.css). Each is marked with the token it
// stands for; here every such token is resolved in theme.css, in the dark and
// in the light theme, and must equal the value written out. And the three
// pages that show the splash (the desktop's, the web app's, the stand's) carry
// the same markup and link it as a file, never inline.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "../../../..");
const read = (p: string) => readFileSync(join(ROOT, p), "utf8");

type Rule = { selector: string; body: string; media: string | null };

/// The style sheet's rules with their bodies, and the media query each sits
/// in; comments dropped. Enough of CSS for a theme file.
function rules(css: string): Rule[] {
  const src = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const out: Rule[] = [];
  const walk = (s: string, media: string | null) => {
    let i = 0;
    while (i < s.length) {
      const open = s.indexOf("{", i);
      if (open < 0) break;
      const head = s.slice(i, open).trim();
      let depth = 1;
      let j = open + 1;
      for (; j < s.length && depth; j++) {
        if (s[j] === "{") depth++;
        else if (s[j] === "}") depth--;
      }
      const body = s.slice(open + 1, j - 1);
      const sel = head.split(";").pop()!.trim();
      if (sel.startsWith("@media")) walk(body, sel);
      else if (!sel.startsWith("@")) out.push({ selector: sel, body, media });
      i = j;
    }
  };
  walk(src, null);
  return out;
}

const decls = (body: string): [string, string][] =>
  [...body.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1]!, m[2]!.trim()]);

/// The tokens of a theme: the dark one is :root's own; the light one is the
/// dark one with the system's light rules over it (those a theme chosen by
/// hand does not take back).
function theme(css: string, light: boolean): Map<string, string> {
  const t = new Map<string, string>();
  for (const r of rules(css)) {
    if (r.media === null && r.selector === ":root") for (const [k, v] of decls(r.body)) t.set(k, v);
  }
  if (light)
    for (const r of rules(css)) {
      if (r.media === "@media (prefers-color-scheme: light)" && /^:root(:not\(\[data-theme="dark"\]\))?$/.test(r.selector)) for (const [k, v] of decls(r.body)) t.set(k, v);
    }
  return t;
}

type Rgb = [number, number, number];
const hex = (s: string): Rgb => {
  const m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(s);
  if (!m) throw new Error(`not a colour: ${s}`);
  const h = m[1]!.length === 3 ? [...m[1]!].map((c) => c + c).join("") : m[1]!;
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16)) as Rgb;
};
const toHex = (c: Rgb) => `#${c.map((x) => Math.round(x).toString(16).padStart(2, "0")).join("")}`;

/// A token's colour: a literal, a var() of another token, or a color-mix in
/// srgb of two opaque colours. Anything else is an error: the splash takes
/// only opaque colours from the theme.
function resolve(t: Map<string, string>, value: string): Rgb {
  const v = value.trim();
  if (v.startsWith("#")) return hex(v);
  const ref = /^var\((--[a-z0-9-]+)\)$/.exec(v);
  if (ref) {
    const next = t.get(ref[1]!);
    if (next === undefined) throw new Error(`no token ${ref[1]}`);
    return resolve(t, next);
  }
  const mix = /^color-mix\(in srgb,\s*(.+?)\s+(\d+(?:\.\d+)?)%\s*,\s*(.+?)(?:\s+(\d+(?:\.\d+)?)%)?\)$/.exec(v);
  if (mix) {
    const p = Number(mix[2]) / 100;
    if (mix[4] !== undefined && Math.abs(Number(mix[4]) / 100 + p - 1) > 1e-9) throw new Error(`a mix that does not add up to 100%: ${v}`);
    const a = resolve(t, mix[1]!);
    const b = resolve(t, mix[3]!);
    return [0, 1, 2].map((i) => a[i]! * p + b[i]! * (1 - p)) as Rgb;
  }
  throw new Error(`cannot resolve "${v}"`);
}

/// The splash's written-out colours and the token each stands for.
function marked(body: string): { name: string; value: string; token: string }[] {
  return [...body.matchAll(/(--s-[a-z-]+)\s*:\s*(#[0-9a-f]{6})\s*;\s*\/\*\s*=\s*(--[a-z0-9-]+)\s*\*\//gi)].map((m) => ({ name: m[1]!, value: m[2]!.toLowerCase(), token: m[3]! }));
}

describe("the splash", () => {
  const themeCss = read("ui/core/src/ui/theme.css");
  const splash = read("ui/core/src/ui/splash.css");
  const at = splash.indexOf("@media (prefers-color-scheme: light)");
  const darkPart = splash.slice(0, at);
  const lightPart = splash.slice(at, splash.indexOf("}", splash.indexOf("}", at) + 1) + 1);

  it("writes out its colours as the theme's tokens, in both themes", () => {
    for (const [part, light] of [
      [darkPart, false],
      [lightPart, true],
    ] as const) {
      const t = theme(themeCss, light);
      const list = marked(part);
      // the ground, the sheet, the text and the accent at least
      expect(list.map((x) => x.token)).toEqual(expect.arrayContaining(["--tier-lo", "--tier-hi", "--text", "--sky"]));
      for (const x of list) expect(`${x.name} ${x.value}`).toBe(`${x.name} ${toHex(resolve(t, `var(${x.token})`))}`);
    }
  });

  it("has no colour that is not marked with its token", () => {
    const literals = [...splash.replace(/\/\*[\s\S]*?\*\//g, "").matchAll(/#[0-9a-f]{3,6}\b/gi)].length;
    expect(literals).toBe(marked(darkPart).length + marked(lightPart).length);
  });

  it("is the same markup in every page, linked as a file", () => {
    const pages = ["gui/app.html", "web/index.html", "ui/stand/index.html"].map((p) => [p, read(p)] as const);
    const markup = pages.map(([p, html]) => {
      const m = /<div id="root">([\s\S]*?)\n {4}<\/div>\n/.exec(html);
      if (!m) throw new Error(`${p} has no splash in #root`);
      expect(m[1]).toContain('class="splash"');
      // nothing inline: no style element, no style attribute, no inline script
      expect(html).not.toMatch(/<style|style="|<script(?![^>]*\bsrc=)/);
      expect(html).toMatch(/<link rel="stylesheet" href="[^"]*splash\.css" \/>/);
      return m[1]!.trim();
    });
    expect(new Set(markup).size).toBe(1);
    for (const p of ["gui/app/splash.css", "web/src/splash.css", "ui/stand/src/splash.css"]) expect(read(p)).toMatch(/@import "[./]+(?:ui\/)?core\/src\/ui\/splash\.css";/);
  });
});
