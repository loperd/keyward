/// The application's palette, out of the person's appearance preference.
///
/// One colour chosen in the preferences paints the whole theme, not a button:
/// the grounds, the columns, the fields, the edges and even the grey of the
/// text take its hue, and the accent line — the main button, the chosen
/// section, the focus ring — takes its colour. Each step keeps the lightness of
/// the native palette, where the contrasts were measured; only the hue and the
/// tint change. So a light colour does not lose the white text on a button,
/// and a dark one does not merge into the navigation.
///
/// The work is done in OKLCH: its lightness is the one the eye sees, so two
/// hues at one L read as equally light — which HSL cannot promise, and yellow
/// and blue at "50%" are nowhere near each other.
///
/// The semantic colours are left alone — green for "done", amber for "mind
/// this", pink for "dangerous", orange for identities and keys: they mean
/// something rather than decorate, and must not follow anybody's taste.

type Oklch = { l: number; c: number; h: number };

/// The grounds and the text: tinted lightly with the hue.
const NEUTRALS = [
  "--ink", "--rail", "--surface", "--panel", "--block", "--field", "--field-focus",
  "--raise", "--edge", "--edge-soft", "--text", "--dim", "--faint",
] as const;

/// The accent line: the colour itself.
const ACCENTS = ["--blue", "--blue-hi", "--sky"] as const;

/// The blocks' tones: neighbours of the colour on the wheel, each keeping the
/// lightness and the strength of the stock tone it replaces — so a block's
/// heading reads as well on its ground as before, only in the palette's hues.
const TONES: Record<string, number> = { "--tone-1": -24, "--tone-2": 24, "--tone-3": 48 };

/// The glass behind the columns, kept as "r g b" for rgb(var(--glass) / a).
const GLASS = "--glass";

const ALL = [...NEUTRALS, ...ACCENTS, ...Object.keys(TONES), GLASS];

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));

function parseHex(hex: string): [number, number, number] | null {
  const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex.trim());
  return m ? [m[1], m[2], m[3]].map((x) => parseInt(x, 16) / 255) as [number, number, number] : null;
}

const toLinear = (v: number) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4);
const toGamma = (v: number) => (v <= 0.0031308 ? 12.92 * v : 1.055 * v ** (1 / 2.4) - 0.055);

function rgbToOklch([r, g, b]: [number, number, number]): Oklch {
  const [lr, lg, lb] = [r, g, b].map(toLinear);
  const l = Math.cbrt(0.4122214708 * lr + 0.5363325363 * lg + 0.0514459929 * lb);
  const m = Math.cbrt(0.2119034982 * lr + 0.6806995451 * lg + 0.1073969566 * lb);
  const s = Math.cbrt(0.0883024619 * lr + 0.2817188376 * lg + 0.6299787005 * lb);
  const L = 0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s;
  const A = 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s;
  const B = 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s;
  return { l: L, c: Math.hypot(A, B), h: ((Math.atan2(B, A) * 180) / Math.PI + 360) % 360 };
}

/// Linear sRGB, not yet clipped: out of [0, 1] means out of gamut.
function oklchToLinear({ l: L, c, h }: Oklch): [number, number, number] {
  const A = c * Math.cos((h * Math.PI) / 180);
  const B = c * Math.sin((h * Math.PI) / 180);
  const l = (L + 0.3963377774 * A + 0.2158037573 * B) ** 3;
  const m = (L - 0.1055613458 * A - 0.0638541728 * B) ** 3;
  const s = (L - 0.0894841775 * A - 1.291485548 * B) ** 3;
  return [
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
  ];
}

/// Into sRGB, giving up chroma rather than lightness when the colour does not
/// fit: the lightness is what the contrasts rest on.
function oklchToRgb(color: Oklch): [number, number, number] {
  const fits = (rgb: number[]) => rgb.every((v) => v >= -1e-4 && v <= 1 + 1e-4);
  let rgb = oklchToLinear(color);
  if (!fits(rgb)) {
    let lo = 0;
    let hi = color.c;
    for (let i = 0; i < 20; i += 1) {
      const mid = (lo + hi) / 2;
      if (fits(oklchToLinear({ ...color, c: mid }))) lo = mid;
      else hi = mid;
    }
    rgb = oklchToLinear({ ...color, c: lo });
  }
  return rgb.map((v) => clamp(toGamma(clamp(v, 0, 1)), 0, 1)) as [number, number, number];
}

const hex = (rgb: number[]) => `#${rgb.map((v) => Math.round(v * 255).toString(16).padStart(2, "0")).join("")}`;

/// The native palette's value of each token for the current scheme, read from
/// the stylesheet itself — one source of truth, not a copy here.
function native(): Record<string, [number, number, number]> {
  const root = document.documentElement;
  for (const v of ALL) root.style.removeProperty(v);
  const style = getComputedStyle(root);
  const out: Record<string, [number, number, number]> = {};
  for (const v of ALL) {
    const raw = style.getPropertyValue(v).trim();
    const rgb = v === GLASS ? raw.split(/\s+/).map((x) => Number(x) / 255) : parseHex(raw);
    if (rgb && rgb.length === 3 && rgb.every((x) => Number.isFinite(x))) out[v] = rgb as [number, number, number];
  }
  return out;
}

/// The native palette's own hue and chroma: the tint of the stock grounds is
/// measured against it, so the default colour reproduces the stock theme.
const STOCK_ACCENT = rgbToOklch(parseHex("#7865f5")!);

/// A whole palette for a colour: every token's value, as the stylesheet would
/// write it. `base` is the native palette of the scheme it is for.
export function paletteFor(color: string, base: Record<string, [number, number, number]>): Record<string, string> | null {
  const rgb = parseHex(color);
  if (!rgb) return null;
  const pick = rgbToOklch(rgb);
  // How colourful the chosen colour is, against the stock accent: a grey gives
  // grey grounds, a vivid colour tints them — a little more than the stock
  // palette does, so that the choice is seen beyond the buttons.
  const vivid = clamp(pick.c / STOCK_ACCENT.c, 0, 1.2);
  const tint = 1.6 * vivid;
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(base)) {
    const own = rgbToOklch(value);
    const isAccent = (ACCENTS as readonly string[]).includes(name);
    const turn = TONES[name];
    const c = isAccent || turn !== undefined ? own.c * clamp(vivid, 0.12, 1.1) : own.c * tint;
    const next = oklchToRgb({ l: own.l, c, h: (pick.h + (turn ?? 0) + 360) % 360 });
    out[name] = name === GLASS ? next.map((v) => Math.round(v * 255)).join(" ") : hex(next);
  }
  return out;
}

/// The palette's tokens for the current scheme, for a preview of a choice;
/// `null` is the native palette. What is applied just now stays applied.
export function previewPalette(color: string | null): Record<string, string> | null {
  const root = document.documentElement;
  const saved = ALL.map((v) => [v, root.style.getPropertyValue(v)] as const);
  const base = native();
  for (const [v, value] of saved) if (value) root.style.setProperty(v, value);
  if (color) return paletteFor(color, base);
  return Object.fromEntries(Object.entries(base).map(([k, v]) => [k, hex(v)]));
}

/// Set the palette from the appearance preference. `null` brings the native
/// palette back.
export function applyAccent(color: string | null | undefined): void {
  const root = document.documentElement;
  const base = native();
  const palette = color ? paletteFor(color, base) : null;
  if (!palette) return;
  for (const [name, value] of Object.entries(palette)) root.style.setProperty(name, value);
}

/// Recompute the palette when the system's theme changes: the steps differ
/// between light and dark. Returns an unsubscribe.
export function watchScheme(recompute: () => void): () => void {
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  mq.addEventListener("change", recompute);
  return () => mq.removeEventListener("change", recompute);
}
