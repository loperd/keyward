// The settings a page shows as live controls: each a row with its words and
// how it reads and changes the settings. A row is a switch or a set of
// choices; what it changes is saved at once. Pure: the page names a row by its
// key, the window draws it against the settings it holds.
import type { Key, Text } from "../i18n";
import { type AppSettings, LanguageChoice, LockAction, type LockTimeout, LockTimeoutKind, type SettingsPatch, ThemeChoice, type UnlockState } from "./types";
import { AccountVerb } from "../verbs/account-ids";

export enum SettingKey {
  LockTimeout = "lockTimeout",
  LockAction = "lockAction",
  Clipboard = "clipboard",
  TouchIdOnLaunch = "touchIdOnLaunch",
  TouchIdForSecrets = "touchIdForSecrets",
  Grace = "grace",
  HideOnCopy = "hideOnCopy",
  Icons = "icons",
  KeepInDock = "keepInDock",
  KeepInTray = "keepInTray",
  StartOnLogin = "startOnLogin",
  ScreenCapture = "screenCapture",
  Theme = "theme",
  Language = "language",
  Biometric = "biometric",
  Pin = "pin",
  Export = "export",
}

export enum RowKind {
  Toggle = "toggle",
  Choice = "choice",
  /// A way to open the vault: whether it is on, and the verbs that turn it
  /// on, change or off.
  Method = "method",
  /// Something done rather than set: a verb's button, no state of its own.
  Action = "action",
}

export type SettingChoice = { label: Text; on: boolean; patch: SettingsPatch };

export type SettingRow =
  | { kind: RowKind.Toggle; title: Key; hint?: (s: AppSettings) => Key; on: (s: AppSettings) => boolean; patch: (on: boolean) => SettingsPatch }
  | { kind: RowKind.Choice; title: Key; hint?: (s: AppSettings) => Key; choices: (s: AppSettings) => SettingChoice[] }
  | { kind: RowKind.Method; title: Key; hint: (u: UnlockState) => Text; on: (u: UnlockState) => boolean; available: (u: UnlockState) => boolean; verbs: (u: UnlockState) => MethodVerb[] }
  | { kind: RowKind.Action; title: Key; hint: Key; verbs: MethodVerb[] };

/// A button of a method's row: the verb it opens.
export type MethodVerb = { label: Key; icon: string; verb: AccountVerb; quiet?: boolean };

const k = (key: Key, args?: Record<string, number>): Text => (args ? { key, args } : { key });

export const LOCK_CHOICES: LockTimeout[] = [
  { kind: LockTimeoutKind.Minutes, minutes: 1 },
  { kind: LockTimeoutKind.Minutes, minutes: 5 },
  { kind: LockTimeoutKind.Minutes, minutes: 15 },
  { kind: LockTimeoutKind.Minutes, minutes: 60 },
  { kind: LockTimeoutKind.OnRestart },
  { kind: LockTimeoutKind.Never },
];
export const CLIPBOARD_CHOICES = [0, 10, 30, 60, 120, 300];
export const GRACE_CHOICES = [0, 60, 300, 900, 3600];

export function lockLabel(v: LockTimeout): Text {
  if (v.kind === LockTimeoutKind.Minutes) return k("set.lock.minutes", { n: v.minutes });
  return k(v.kind === LockTimeoutKind.OnRestart ? "set.lock.onRestart" : "set.lock.never");
}
const sameLock = (a: LockTimeout, b: LockTimeout) => a.kind === b.kind && (a.kind !== LockTimeoutKind.Minutes || (b.kind === LockTimeoutKind.Minutes && a.minutes === b.minutes));

/// Seconds as the choices name them: never, seconds, then minutes.
function secondsLabel(sec: number, zero: Key): Text {
  if (sec === 0) return k(zero);
  return sec < 60 ? k("set.seconds", { n: sec }) : k("set.minutes", { n: Math.round(sec / 60) });
}

/// The choices of a number setting: the known ones, and the one in force
/// should it be none of them (set by hand in the file), so the row never
/// shows nothing chosen.
function numberChoices(known: number[], now: number, zero: Key, patch: (n: number) => SettingsPatch): SettingChoice[] {
  const all = known.includes(now) ? known : [...known, now].sort((a, b) => a - b);
  return all.map((n) => ({ label: secondsLabel(n, zero), on: n === now, patch: patch(n) }));
}

function toggle(title: Key, on: (s: AppSettings) => boolean, patch: (on: boolean) => SettingsPatch, hint?: Key): SettingRow {
  return { kind: RowKind.Toggle, title, on, patch, ...(hint ? { hint: () => hint } : {}) };
}

export const ROWS: Record<SettingKey, SettingRow> = {
  [SettingKey.LockTimeout]: {
    kind: RowKind.Choice,
    title: "set.lock",
    hint: () => "set.lockHint",
    choices: (s) => {
      const known = LOCK_CHOICES.some((c) => sameLock(c, s.lockTimeout)) ? LOCK_CHOICES : [...LOCK_CHOICES, s.lockTimeout];
      return known.map((c) => ({ label: lockLabel(c), on: sameLock(c, s.lockTimeout), patch: { lockTimeout: c } }));
    },
  },
  [SettingKey.LockAction]: {
    kind: RowKind.Choice,
    title: "set.lockAction",
    hint: (s) => (s.lockAction === LockAction.Logout ? "set.lockAction.logoutHint" : "set.lockAction.lockHint"),
    choices: (s) => [
      { label: k("set.lockAction.lock"), on: s.lockAction === LockAction.Lock, patch: { lockAction: LockAction.Lock } },
      { label: k("set.lockAction.logout"), on: s.lockAction === LockAction.Logout, patch: { lockAction: LockAction.Logout } },
    ],
  },
  [SettingKey.Clipboard]: {
    kind: RowKind.Choice,
    title: "set.clipboard",
    hint: () => "set.clipboardHint",
    choices: (s) => numberChoices(CLIPBOARD_CHOICES, s.clipboardClearSeconds, "set.never", (n) => ({ clipboardClearSeconds: n })),
  },
  [SettingKey.TouchIdOnLaunch]: toggle("set.touchIdLaunch", (s) => s.touchIdOnLaunch, (on) => ({ touchIdOnLaunch: on })),
  [SettingKey.TouchIdForSecrets]: toggle("set.touchIdSecrets", (s) => s.touchIdForSecrets, (on) => ({ touchIdForSecrets: on }), "set.touchIdSecretsHint"),
  [SettingKey.Grace]: {
    kind: RowKind.Choice,
    title: "set.grace",
    hint: () => "set.graceHint",
    choices: (s) => numberChoices(GRACE_CHOICES, s.biometricGraceSeconds, "set.grace.always", (n) => ({ biometricGraceSeconds: n })),
  },
  [SettingKey.HideOnCopy]: toggle("set.hideOnCopy", (s) => s.hideOnCopy, (on) => ({ hideOnCopy: on }), "set.hideOnCopyHint"),
  [SettingKey.Icons]: toggle("set.icons", (s) => s.showWebsiteIcons, (on) => ({ showWebsiteIcons: on }), "set.iconsHint"),
  [SettingKey.KeepInDock]: toggle("set.keepInDock", (s) => s.keepInDock, (on) => ({ keepInDock: on }), "set.keepInDockHint"),
  [SettingKey.KeepInTray]: toggle("set.keepInTray", (s) => s.keepInTray, (on) => ({ keepInTray: on }), "set.keepInTrayHint"),
  [SettingKey.StartOnLogin]: toggle("set.startOnLogin", (s) => s.startOnLogin, (on) => ({ startOnLogin: on }), "set.startOnLoginHint"),
  [SettingKey.ScreenCapture]: toggle("set.screenCapture", (s) => s.allowScreenCapture, (on) => ({ allowScreenCapture: on }), "set.screenCaptureHint"),
  [SettingKey.Theme]: {
    kind: RowKind.Choice,
    title: "set.theme",
    choices: (s) =>
      [ThemeChoice.System, ThemeChoice.Dark, ThemeChoice.Light].map((v) => ({ label: k(`set.theme.${v}`), on: s.theme === v, patch: { theme: v } })),
  },
  [SettingKey.Biometric]: {
    kind: RowKind.Method,
    title: "set.biometric",
    hint: (u) => (u.biometricProblem !== null && !u.biometric ? { key: "set.biometric.unavailable", args: { reason: u.biometricProblem } } : k(u.biometric ? "set.biometric.on" : "set.biometric.off")),
    on: (u) => u.biometric,
    // A sensor that cannot be used is no reason to keep a key that was
    // remembered behind it: turning it off is always offered.
    available: (u) => u.biometric || u.biometricProblem === null,
    verbs: (u) => (u.biometric ? [{ label: "set.turnOff", icon: "finger", verb: AccountVerb.TouchIdOff, quiet: true }] : [{ label: "set.turnOn", icon: "finger", verb: AccountVerb.TouchIdOn }]),
  },
  [SettingKey.Pin]: {
    kind: RowKind.Method,
    title: "set.pin",
    hint: (u) => k(u.pin ? "set.pin.on" : "set.pin.off"),
    on: (u) => u.pin,
    available: () => true,
    verbs: (u) =>
      u.pin
        ? [
            { label: "set.change", icon: "hash", verb: AccountVerb.Pin, quiet: true },
            { label: "set.turnOff", icon: "hash", verb: AccountVerb.PinOff, quiet: true },
          ]
        : [{ label: "set.turnOn", icon: "hash", verb: AccountVerb.Pin }],
  },
  [SettingKey.Export]: { kind: RowKind.Action, title: "set.export", hint: "set.exportHint", verbs: [{ label: "set.exportGo", icon: "ext", verb: AccountVerb.Export }] },
  [SettingKey.Language]: {
    kind: RowKind.Choice,
    title: "set.language",
    hint: () => "set.languageHint",
    choices: (s) =>
      [LanguageChoice.Auto, LanguageChoice.Ru, LanguageChoice.En].map((v) => ({ label: k(`set.language.${v}`), on: s.language === v, patch: { language: v } })),
  },
};
