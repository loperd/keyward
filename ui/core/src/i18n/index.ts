// The window's words. Every text a person reads goes through a key here; the
// Russian dictionary is the reference, so a key missing in English is a
// compile error, not a blank label. Counted phrases use the language's own
// plural rules (Intl.PluralRules), never a hand-made `n === 1`.
//
// A plugin brings words of its own: it registers a dictionary under its name
// and names its texts `{ ext: "ssh.hosts" }`. Its keys are not known at
// compile time, so a missing one fails loudly when it is read.
import ruCore from "./ru.json";
import enCore from "./en.json";
import ruMap from "./map.ru.json";
import enMap from "./map.en.json";
import ruReprompt from "./reprompt.ru.json";
import enReprompt from "./reprompt.en.json";
import ruSettings from "./settings.ru.json";
import enSettings from "./settings.en.json";

// The dictionaries are kept in files by area (the map's words apart, the
// re-prompt's apart, the settings' apart), and read as one.
const ru = { ...ruCore, ...ruMap, ...ruReprompt, ...ruSettings };
const en = { ...enCore, ...enMap, ...enReprompt, ...enSettings };

export enum Lang {
  Ru = "ru",
  En = "en",
}
export type Key = keyof typeof ru;
type Entry = string | Partial<Record<Intl.LDMLPluralRule, string>>;
type Dictionary = Record<Key, Entry>;

const DICTIONARIES: Record<Lang, Dictionary> = { ru, [Lang.En]: en satisfies Record<Key, Entry> };
export const LANGS: Lang[] = [Lang.Ru, Lang.En];

let lang: Lang = Lang.Ru;
const listeners = new Set<(l: Lang) => void>();

export const currentLang = () => lang;
export function setLang(next: Lang) {
  lang = next;
  for (const l of listeners) l(next);
}
export function onLang(cb: (l: Lang) => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

/// A text to show: a key of the core's dictionary, a key of a plugin's, or a
/// name from the data, which is shown as it is (an item's name is not
/// translated).
export type Text =
  | { key: Key; args?: Args }
  | { ext: string; args?: Args }
  | { raw: string };
/// A text's arguments; an argument may be a text itself, read in the language
/// of the moment ("{role} · {n} members" with the role translated too).
export type Args = Record<string, Arg>;
/// An argument: a word, a number, a text, or a list read the language's way
/// ("Marco и Tomás", "Marco and Tomás").
export type Arg = string | number | Text | { list: (string | Text)[] };

/// A plugin's words: every key in every language the window speaks.
export type Words = Record<Lang, Record<string, Entry>>;
const EXT = new Map<string, Words>();

/// Registers a plugin's dictionary under its name; `ssh.hosts` is then the
/// key `hosts` of `ssh`. Both languages must carry the same keys, so a
/// dictionary that does not is refused rather than half shown.
export function registerWords(ns: string, words: Words) {
  const ref = Object.keys(words.ru).sort().join("\n");
  for (const l of LANGS) {
    const ks = Object.keys(words[l]).sort().join("\n");
    if (ks !== ref) throw new Error(`the words of "${ns}" in ${l} do not match its Russian keys`);
  }
  EXT.set(ns, words);
}

/// Forgets a plugin's dictionary: a plugin's words may name what it found in
/// the vault, so they go when the session closes.
export function unregisterWords(ns: string) {
  EXT.delete(ns);
}

// boundary: `Intl.ListFormat`'s own option, not a state.
const arg = (v: Arg): string => {
  if (typeof v !== "object") return String(v);
  if ("list" in v) return new Intl.ListFormat(lang, { type: "conjunction" }).format(v.list.map((x) => (typeof x === "string" ? x : text(x))));
  return text(v);
};
const fill = (s: string, args?: Args) => (args ? s.replace(/\{(\w+)\}/g, (m, k: string) => (k in args ? arg(args[k]!) : m)) : s);

function pick(entry: Entry | undefined, name: string, args?: Args): string {
  if (entry === undefined) throw new Error(`no word "${name}" in ${lang}`);
  if (typeof entry === "string") return fill(entry, args);
  const n = args?.n;
  if (typeof n !== "number") throw new Error(`"${name}" is counted and needs a number n`);
  const form = new Intl.PluralRules(lang).select(n);
  const s = entry[form] ?? entry.other ?? entry.many;
  if (s === undefined) throw new Error(`"${name}" has no "${form}" form in ${lang}`);
  return fill(s, args);
}

export function t(key: Key, args?: Args): string {
  return pick(DICTIONARIES[lang][key], key, args);
}

function extEntry(name: string, l: Lang): Entry {
  const dot = name.indexOf(".");
  const ns = dot > 0 ? name.slice(0, dot) : "";
  const words = EXT.get(ns);
  if (!words) throw new Error(`no dictionary "${ns}" for "${name}"`);
  const e = words[l][name.slice(dot + 1)];
  if (e === undefined) throw new Error(`no word "${name}" in ${l}`);
  return e;
}
export function tx(name: string, args?: Args): string {
  return pick(extEntry(name, lang), name, args);
}

export const text = (x: Text): string => ("raw" in x ? x.raw : "ext" in x ? tx(x.ext, x.args) : t(x.key, x.args));
export const isKey = (k: string): k is Key => k in ru;
export const key = (k: Key, args?: Args): Text => (args ? { key: k, args } : { key: k });
export const raw = (s: string): Text => ({ raw: s });

/// A key's plain text in every dictionary, lowercased, as a person would type
/// it: what lets "участники" and "members" reach the same step.
export function allTexts(key: Key): string[] {
  return (Object.values(DICTIONARIES) as Dictionary[])
    .map((d) => d[key])
    .filter((e): e is string => typeof e === "string")
    .map((s) => s.toLowerCase());
}
/// The same for a text of any kind.
export function textsOf(x: Text): string[] {
  if ("raw" in x) return [x.raw.toLowerCase()];
  if ("key" in x) return allTexts(x.key);
  return LANGS.map((l) => extEntry(x.ext, l))
    .filter((e): e is string => typeof e === "string")
    .map((s) => s.toLowerCase());
}
