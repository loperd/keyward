// The settings' pages: the steps under Settings on the path, each a document
// of sections whose rows are live controls (rows.ts). Which pages there are is
// the app's: the web app has none, an app without Touch ID has no Unlocking.
// Pure.
import type { Key } from "../i18n";
import { type DocSpec, Hue, LeadTile, LiveBlock, type Section } from "../doc/spec";
import { SettingKey } from "./rows";

export enum SettingsPage {
  Account = "account",
  Security = "security",
  Unlock = "unlock",
  Browsers = "browsers",
  App = "app",
}

export const SETTINGS_ID = "settings";
export const pageId = (p: SettingsPage) => `${SETTINGS_ID}/${p}`;

export const PAGE_ICON: Record<SettingsPage, string> = {
  [SettingsPage.Account]: "person",
  [SettingsPage.Security]: "shield",
  [SettingsPage.Unlock]: "finger",
  [SettingsPage.Browsers]: "login",
  [SettingsPage.App]: "window",
};
export const PAGE_NAME: Record<SettingsPage, Key> = {
  [SettingsPage.Account]: "set.page.account",
  [SettingsPage.Security]: "set.page.security",
  [SettingsPage.Unlock]: "set.page.unlock",
  [SettingsPage.Browsers]: "set.page.browsers",
  [SettingsPage.App]: "set.page.app",
};
const PAGE_SUB: Record<SettingsPage, Key> = {
  [SettingsPage.Account]: "set.page.accountSub",
  [SettingsPage.Security]: "set.page.securitySub",
  [SettingsPage.Unlock]: "set.page.unlockSub",
  [SettingsPage.Browsers]: "set.page.browsersSub",
  [SettingsPage.App]: "set.page.appSub",
};
export const pageSub = (p: SettingsPage): Key => PAGE_SUB[p];

const rows = (title: Key, keys: SettingKey[]): Section => ({ title: { key: title }, blocks: keys.map((setting) => ({ setting })) });

const SECTIONS: Record<SettingsPage, Section[]> = {
  [SettingsPage.Account]: [
    { title: { key: "set.sec.profile" }, blocks: [{ live: LiveBlock.Profile }] },
    { title: { key: "set.sec.signIn" }, blocks: [{ live: LiveBlock.Email }, { setting: SettingKey.Password }, { setting: SettingKey.Kdf }] },
    { title: { key: "set.sec.twoFactor" }, blocks: [{ live: LiveBlock.TwoFactor }] },
    rows("set.sec.danger", [SettingKey.SignOutEverywhere, SettingKey.Purge, SettingKey.DeleteAccount]),
  ],
  [SettingsPage.Security]: [rows("set.sec.timeout", [SettingKey.LockTimeout, SettingKey.LockAction]), rows("set.sec.clipboard", [SettingKey.Clipboard]), rows("set.sec.export", [SettingKey.Export])],
  [SettingsPage.Unlock]: [rows("set.sec.touchId", [SettingKey.Biometric, SettingKey.TouchIdOnLaunch, SettingKey.TouchIdForSecrets, SettingKey.Grace]), rows("set.sec.pin", [SettingKey.Pin])],
  [SettingsPage.Browsers]: [{ title: { key: "set.sec.extensions" }, blocks: [{ live: LiveBlock.Extensions }] }],
  [SettingsPage.App]: [
    rows("set.sec.window", [SettingKey.HideOnCopy, SettingKey.KeepInDock, SettingKey.KeepInTray, SettingKey.StartOnLogin, SettingKey.ScreenCapture]),
    rows("set.sec.look", [SettingKey.Theme, SettingKey.Language, SettingKey.Icons]),
  ],
};

/// A settings page's document.
export function pageDoc(p: SettingsPage): DocSpec {
  return {
    hero: { lead: { tile: LeadTile.Icon, icon: PAGE_ICON[p], hue: Hue.Cyan }, title: { key: PAGE_NAME[p] }, place: [SETTINGS_ID], what: { key: PAGE_SUB[p] } },
    sections: SECTIONS[p],
  };
}

/// The settings' own document: what each page holds, a line to each.
export function settingsDoc(pages: SettingsPage[]): DocSpec {
  return {
    hero: { lead: { tile: LeadTile.Icon, icon: "settings", hue: Hue.Cyan }, title: { key: "set.title" }, place: [], what: { key: "set.what" } },
    sections: [
      {
        title: { key: "set.pages" },
        blocks: pages.map((p) => ({ ref: pageId(p), lead: { tile: LeadTile.Plain, icon: PAGE_ICON[p] }, title: { key: PAGE_NAME[p] }, context: { key: PAGE_SUB[p] } })),
      },
    ],
  };
}
