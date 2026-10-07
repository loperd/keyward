// What of the settings the window itself carries out: its theme and its
// language. The rest (the Dock, the clipboard, the timeout) is the app's.
import { Lang, setLang } from "../i18n";
import { type AppSettings, LanguageChoice, ThemeChoice } from "./types";

/// The language a choice means here: "auto" follows the system's.
export function langOf(choice: LanguageChoice, system: string): Lang {
  if (choice === LanguageChoice.Ru) return Lang.Ru;
  if (choice === LanguageChoice.En) return Lang.En;
  return system.toLowerCase().startsWith("ru") ? Lang.Ru : Lang.En;
}

/// Puts the theme and the language in force.
export function applyLook(s: AppSettings, root: HTMLElement = document.documentElement, system: string = navigator.language) {
  if (s.theme === ThemeChoice.System) delete root.dataset.theme;
  else root.dataset.theme = s.theme;
  setLang(langOf(s.language, system));
}
