// The app's settings, as the window reads and changes them: when the vault
// locks, how the clipboard and Touch ID behave, what the window does on
// close, its theme and language. The desktop app keeps them in the daemon
// (`~/.keyward/settings.json`); the web app has none. The enums' values are
// the daemon's words, so a backend parses them once at its boundary.
import { enumParser } from "../model/enum";

/// When the vault locks by itself.
export enum LockTimeoutKind {
  OnRestart = "on_restart",
  Minutes = "minutes",
  Never = "never",
}
export const parseLockTimeoutKind = enumParser(LockTimeoutKind, "a lock timeout");
export type LockTimeout = { kind: LockTimeoutKind.OnRestart } | { kind: LockTimeoutKind.Minutes; minutes: number } | { kind: LockTimeoutKind.Never };

/// What the timeout does: forget the keys, or sign the account out entirely.
export enum LockAction {
  Lock = "lock",
  Logout = "logout",
}
export const parseLockAction = enumParser(LockAction, "a lock action");

export enum ThemeChoice {
  System = "system",
  Dark = "dark",
  Light = "light",
}
export const parseThemeChoice = enumParser(ThemeChoice, "a theme");

export enum LanguageChoice {
  Auto = "auto",
  Ru = "ru",
  En = "en",
}
export const parseLanguageChoice = enumParser(LanguageChoice, "a language");

export type AppSettings = {
  lockTimeout: LockTimeout;
  lockAction: LockAction;
  touchIdOnLaunch: boolean;
  touchIdForSecrets: boolean;
  /// 0: the clipboard is never cleared.
  clipboardClearSeconds: number;
  /// How long after a Touch ID the daemon does not ask again; 0: every time.
  biometricGraceSeconds: number;
  showWebsiteIcons: boolean;
  hideOnCopy: boolean;
  keepInTray: boolean;
  keepInDock: boolean;
  allowScreenCapture: boolean;
  startOnLogin: boolean;
  theme: ThemeChoice;
  /// `#rrggbb`, or the palette's own accent.
  accentColor: string | null;
  language: LanguageChoice;
};

export type SettingsPatch = Partial<AppSettings>;

/// How the account opens on this computer besides the master password.
/// `biometricProblem`: why Touch ID cannot be used here, if it cannot.
export type UnlockState = { biometric: boolean; biometricProblem: string | null; pin: boolean };

/// A browser extension that may ask for passkeys, or asks to: its key's five
/// words, compared with the extension's own window; `at` and `expires` are
/// seconds since the epoch (`expires` is 0 for a paired one).
export type BrowserExtension = { key: string; words: string[]; at: number; expires: number };
export type BrowserExtensions = { paired: BrowserExtension[]; pending: BrowserExtension[] };
