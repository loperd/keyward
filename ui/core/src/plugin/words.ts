// A plugin's words as it declares them — a key of its dictionary with
// arguments, or a value as it is — read into the core's texts. Its places and
// its screens are read alike: a key its dictionary lacks is refused, by the
// plugin's name, where it is read, never shown as a bare key.
import type { Arg, Args, Text, Words } from "../i18n";

/// A word: a key of the plugin's dictionary, with arguments, or a value.
export type DeclaredText = { key: string; args?: Record<string, unknown> | null } | { raw: string };

/// The plugin's reader of words: `text` reads one word said at `where`,
/// `fail` refuses the declaration.
export type WordReader = {
  text: (t: DeclaredText | undefined | null, where: string) => Text;
  opt: (t: DeclaredText | undefined | null, where: string) => Text | undefined;
};

export function wordReader(plugin: string, words: Words | undefined, fail: (what: string) => never): WordReader {
  const text = (t: DeclaredText | undefined | null, where: string): Text => {
    if (!t || typeof t !== "object") return fail(`no words for ${where}`);
    if ("raw" in t) {
      if (typeof t.raw !== "string") return fail(`a value that is not text in ${where}`);
      return { raw: t.raw };
    }
    if (typeof t.key !== "string") return fail(`a text with no key in ${where}`);
    if (!words) return fail(`the word "${t.key}" in ${where} and brings no dictionary`);
    for (const l of Object.keys(words) as (keyof Words)[]) if (!(t.key in words[l])) fail(`the word "${t.key}" in ${where}, which its ${l} dictionary lacks`);
    const ext = `${plugin}.${t.key}`;
    return t.args ? { ext, args: args(t.args, where) } : { ext };
  };
  const args = (a: Record<string, unknown>, where: string): Args => {
    const out: Args = {};
    for (const [k, v] of Object.entries(a)) out[k] = arg(v, `${where} (${k})`);
    return out;
  };
  const arg = (v: unknown, where: string): Arg => {
    if (typeof v === "string" || typeof v === "number") return v;
    if (Array.isArray(v)) return { list: v.map((x) => (typeof x === "string" ? x : text(x as DeclaredText, where))) };
    if (v && typeof v === "object") return text(v as DeclaredText, where);
    return fail(`an argument that is neither text nor a number in ${where}`);
  };
  const opt = (t: DeclaredText | undefined | null, where: string): Text | undefined => (t === undefined || t === null ? undefined : text(t, where));
  return { text, opt };
}
