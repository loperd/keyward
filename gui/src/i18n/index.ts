import { en } from "./en";
import { ru, type Key } from "./ru";

/// The language is an application setting (`settings.language`): as the system
/// has it, Russian, or English. The settings do not arrive from the daemon at
/// once, so the last applied value lies in `localStorage`: the first frame is
/// drawn in the right language rather than in the system's and then changed.
const dictionaries = { ru, en } as const;
export type Lang = keyof typeof dictionaries;
export type LangPref = "auto" | Lang;

const STORAGE_KEY = "lang";

function systemLang(): Lang {
  const raw = (navigator.language || "en").toLowerCase();
  return raw.startsWith("ru") ? "ru" : "en";
}

function storedPref(): LangPref {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    return v === "ru" || v === "en" || v === "auto" ? v : "auto";
  } catch {
    return "auto";
  }
}

function resolve(pref: LangPref): Lang {
  return pref === "auto" ? systemLang() : pref;
}

export function detectLang(): Lang {
  // The harness needs a way to capture both languages: the captions differ in
  // length, and catching clipping in one locale catches half of it.
  const forced = new URLSearchParams(window.location.search).get("lang");
  if (forced === "ru" || forced === "en") return forced;
  return resolve(storedPref());
}

let lang: Lang = detectLang();
let dict: Record<Key, string> = dictionaries[lang];

export function currentLang(): Lang {
  return lang;
}

/// An event for whoever keeps translations in state: `App` redraws its tree on
/// it, and every `t()` in the markup takes the new dictionary.
export const LANG_EVENT = "keyward:lang";

/// Applies the language setting. Returns `true` when the dictionary
/// changed.
export function setLanguage(pref: LangPref): boolean {
  // A harness run with `?lang=` is captured in the language it names, and the
  // setting does not override it.
  const forced = new URLSearchParams(window.location.search).get("lang");
  if (forced === "ru" || forced === "en") return false;
  try {
    localStorage.setItem(STORAGE_KEY, pref);
  } catch {
    /* it works without storage too: the first frame is simply the system's */
  }
  const next = resolve(pref);
  if (next === lang) return false;
  lang = next;
  dict = dictionaries[lang];
  document.documentElement.lang = lang;
  window.dispatchEvent(new Event(LANG_EVENT));
  return true;
}

/// A translation by key, with `{name}` filled in.
export function t(key: Key, vars?: Record<string, string | number>): string {
  const template = dict[key];
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in vars ? String(vars[name]) : whole,
  );
}

/// A translation that may not exist. Section captions arrive on plugins'
/// cards: the dictionary knows nothing about somebody else's plugin, and then
/// what the plugin called itself is shown.
export function tMaybe(key: string, fallback: string): string {
  return (dict as Record<string, string | undefined>)[normalKey(key)] ?? fallback;
}

/// Every key is camelCase, segment by segment (`err.vaultLocked`). A key in
/// the old snake_case — in an edit's saved error, or from a plugin not rebuilt
/// yet — is the same key, and is read as such.
export function normalKey(key: string): string {
  return /^[\w.]+$/.test(key) ? key.replace(/_([a-z0-9])/gi, (_, c: string) => c.toUpperCase()) : key;
}

/// A translation of an error message. The daemon gives codes of the form
/// `err.badPassword`, and when a message has a variable part, the code
/// followed by an object of values:
/// `err.totpSeedBadAlphabet {"total":"16","outside":"3"}`. Anything
/// unfamiliar is shown as it is, so that no diagnosis is lost.
export function tError(message: string): string {
  const cleaned = message.replace(/^Error:\s*/, "").trim();
  if (normalKey(cleaned) in dict) return dict[normalKey(cleaned) as Key];
  const split = /^([\w.]+)\s+(\{.*\})$/s.exec(cleaned);
  if (split) split[1] = normalKey(split[1]);
  if (split && split[1] in dict) {
    try {
      const vars = JSON.parse(split[2]) as Record<string, string>;
      // A value that turned out to be a key itself is translated: that is how
      // the daemon passes the name of a permission — it does not know the
      // language of the window that asked.
      for (const name of Object.keys(vars)) {
        const value = vars[name];
        if (typeof value === "string" && normalKey(value) in dict) vars[name] = dict[normalKey(value) as Key];
      }
      return t(split[1] as Key, vars);
    } catch {
      return dict[split[1] as Key];
    }
  }
  return cleaned || t("err.unknown");
}

/// The locale for dates and numbers, the same as the dictionary's.
export function locale(): string {
  return lang === "ru" ? "ru-RU" : "en-US";
}

export type { Key };
