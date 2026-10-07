// What the core asks of an app. The desktop app answers through the daemon
// (keys never leave it); the web app answers from the tab, against the one
// server it was deployed for. The core holds no secret in its state: values
// cross this boundary only when a person copies or reveals one, and a
// revealed value is the caller's to drop.
import type { Catalog, ItemDetail, SecretRef, Totp } from "./model/types";
import type { Contribution } from "./path/directory";
import type { PluginCall } from "./verbs/spec";
import { enumParser } from "./model/enum";
import type { AppSettings, SettingsPatch } from "./settings/types";

/// What a session is doing: the state of the app's session, and of each of
/// its accounts.
export enum SessionState {
  NeedsSetup = "needsSetup",
  LoggedOut = "loggedOut",
  Locked = "locked",
  Unlocked = "unlocked",
  Damaged = "damaged",
}
export const parseSessionState = enumParser(SessionState, "a session state");

export type Session =
  | { state: SessionState.NeedsSetup }
  | { state: SessionState.LoggedOut; email: string | null; server: string }
  /// `biometric` and `pin`: whether this account has Touch ID or a PIN set
  /// up for unlocking (undefined where the backend cannot tell).
  | { state: SessionState.Locked; email: string; server: string; biometric?: boolean; pin?: boolean }
  | { state: SessionState.Unlocked; email: string; server: string; name: string | null }
  /// The vault cannot be opened as it stands: a saved session that does not
  /// read (`reason` is the backend's code, `err.*`), or a vault switched off.
  /// `canReset`: `resetSession` forgets the damaged session, and the person
  /// signs in again.
  | { state: SessionState.Damaged; email: string | null; server: string | null; reason: string; canReset: boolean };

/// An account the app is signed in to, where there can be several
/// (`caps.accounts`). `active`: the one the window shows.
export type Account = { id: string; email: string; server: string; active: boolean; state: SessionState };

/// What an app can do; the window shows only what is there. The web app has
/// one fixed server, one account, no daemon and no plugins.
export type Capabilities = {
  /// A person may point the app at a server of their choosing.
  chooseServer: boolean;
  /// More than one account side by side.
  accounts: boolean;
  /// Touch ID and the like.
  biometric: boolean;
  /// Plugins add places (SSH, Kubernetes).
  plugins: boolean;
  /// The backend clears the clipboard itself after a copy.
  clipboardClears: boolean;
};

/// Where a sign-in stands after a call: through, or asking for more.
export enum LoginStepKind {
  Done = "done",
  TwoFactor = "twoFactor",
  NewDevice = "newDevice",
}
export const parseLoginStepKind = enumParser(LoginStepKind, "a sign-in step");
export type LoginStep =
  | { step: LoginStepKind.Done }
  | { step: LoginStepKind.TwoFactor; providers: TwoFactorProvider[] }
  | { step: LoginStepKind.NewDevice };
export enum TwoFactorProvider {
  Authenticator = "authenticator",
  Email = "email",
  WebAuthn = "webauthn",
  Yubikey = "yubikey",
  Duo = "duo",
  Recovery = "recovery",
}
export const parseTwoFactorProvider = enumParser(TwoFactorProvider, "a second factor");

/// A secret shown for a moment. The window renders `value` and calls `drop`
/// when it hides it (on blur, on timeout, on unmount).
export type Revealed = { value: string; drop: () => void };

/// What the clipboard holds of a copy: nothing (`idle`), a secret whose
/// clear is not due yet (`waiting`), or a secret whose clear is overdue
/// (`stuck`).
export enum ClipboardState {
  Idle = "idle",
  Waiting = "waiting",
  Stuck = "stuck",
}

/// What a copy left: in how many seconds the backend clears the clipboard,
/// or `null` where it will not (a value that is no secret, clearing turned
/// off).
export type Copied = { clearsIn: number | null };

/// What changed, so the window refreshes only what it must.
export enum ChangeKind {
  Session = "session",
  Catalog = "catalog",
  Item = "item",
}
export const parseChangeKind = enumParser(ChangeKind, "a change");
export type Change = { kind: ChangeKind.Session } | { kind: ChangeKind.Catalog } | { kind: ChangeKind.Item; id: string };

/// The desktop app's two windows, while they live side by side.
export enum InterfaceChoice {
  New = "new",
  Old = "old",
}

export interface Backend {
  readonly caps: Capabilities;

  session(): Promise<Session>;
  /// Changes made elsewhere (a sync, another window, a lock on idle).
  subscribe(cb: (c: Change) => void): () => void;

  /// `identityUrl`: a self-hosted server's separate identity service, where
  /// the person gave one (only with `caps.chooseServer`).
  login(input: { server?: string; identityUrl?: string; email: string; password: string }): Promise<LoginStep>;
  twoFactor(input: { provider: TwoFactorProvider; code: string; remember: boolean }): Promise<LoginStep>;
  unlock(password: string): Promise<void>;
  /// Touch ID and the like; present only where `caps.biometric`.
  unlockBiometric?(): Promise<void>;
  /// The PIN set for this account on this device.
  unlockPin?(pin: string): Promise<void>;
  /// Sends the code by email (again): the second factor's for `"email"`, or
  /// the new device's after `{ step: "newDevice" }`, whatever `provider` says.
  sendTwoFactorCode?(provider: TwoFactorProvider): Promise<void>;
  lock(): Promise<void>;
  logout(): Promise<void>;
  sync(): Promise<void>;
  /// Forgets a damaged session (`{ state: "damaged", canReset: true }`) so the
  /// person can sign in again.
  resetSession?(): Promise<void>;

  /// The accounts side by side; present only where `caps.accounts`.
  accounts?(): Promise<Account[]>;
  /// Makes another account the active one; the session changes.
  switchAccount?(id: string): Promise<void>;
  /// Makes room for one more account: the session reads `needsSetup` until a
  /// sign-in or a switch.
  addAccount?(): Promise<void>;

  catalog(): Promise<Catalog>;
  /// Places plugins add under the root; empty where there are none.
  contributions(): Promise<Contribution[]>;
  item(id: string): Promise<ItemDetail>;

  /// The backend puts the secret on the clipboard (and clears it after).
  copy(ref: SecretRef): Promise<Copied>;
  reveal(ref: SecretRef): Promise<Revealed>;
  totp(itemId: string): Promise<Totp>;
  /// An item marked `reprompt` shows and copies nothing until the master
  /// password is checked again: the window asks for it and calls this before
  /// each copy, reveal or code of such an item; a wrong password rejects.
  /// Absent where the backend enforces the re-prompt itself (the daemon asks
  /// for Touch ID): the window then calls copy/reveal/totp directly.
  verifyReprompt?(itemId: string, password: string): Promise<void>;
  /// What the clipboard holds of the backend's copies, where the backend
  /// clears it itself (`caps.clipboardClears`): `"stuck"` means the clear
  /// was due and could not be done (a browser writes the clipboard only for
  /// a focused page) — the clipboard still holds a secret, and the window
  /// says so until it turns `"idle"`. Absent where the backend cannot tell.
  clipboardState?(): ClipboardState;
  /// Every change of `clipboardState()`; returns the unsubscribe. Separate
  /// from `subscribe`: it is no change of the vault.
  watchClipboard?(cb: (s: ClipboardState) => void): () => void;

  trash(ids: string[]): Promise<void>;
  restore(ids: string[]): Promise<void>;
  purge(ids: string[]): Promise<void>;

  /// Carries out one of a plugin's actions (a verb a plugin declared);
  /// present only where `caps.plugins`. What it changed comes back as a
  /// change of the catalogue.
  pluginAct?(call: PluginCall): Promise<void>;

  /// The app's settings; present only where the app keeps any (the desktop
  /// app). Without them there is no Settings on the path.
  settings?(): Promise<AppSettings>;
  /// Changes some of them and answers with all of them as they now stand.
  setSettings?(patch: SettingsPatch): Promise<AppSettings>;

  /// The desktop app's choice of window, while the old one and this one live
  /// side by side: saves it and reloads the window into that page. Absent
  /// where there is no other window to go to.
  setInterface?(ui: InterfaceChoice): Promise<void>;
}
