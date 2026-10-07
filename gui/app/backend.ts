// The desktop app's backend: the daemon, through the window's Rust half.
// Keys never leave the daemon; a secret comes to this page only sealed
// (`invokeSecret`, ECDH + AES-GCM per window) and only when it is revealed.
// A copy never touches the page at all — the daemon puts it on the clipboard
// and clears it there.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  type Account,
  type Backend,
  type Capabilities,
  type Catalog,
  type Change,
  type Copied,
  type Item,
  type ItemDetail,
  type LoginStep,
  type Member,
  type Session,
  type SecretRef,
  type Totp,
  TwoFactorProvider,
  SessionState,
  LoginStepKind,
  SecretField,
  Permission,
  OrgRole,
  MemberStatus,
  ChangeKind,
  InterfaceChoice,
  enumParser,
  parseItemKind,
  parseMemberStatus,
  parseOrgRole,
  type AppSettings,
  type LockTimeout,
  LockTimeoutKind,
  type SettingsPatch,
  parseLanguageChoice,
  parseLockAction,
  parseLockTimeoutKind,
  parseThemeChoice,
  type UnlockState,
  AccountOp,
  type AccountWrite,
  type BrowserExtension,
  type BrowserExtensions,
  type AccountProfile,
  type TwoFactorStatus as CoreTwoFactorStatus,
  type Revealed,
  type FillContext,
  FillMode,
  type Kdf,
  KdfKind,
  parseKdfKind,
} from "@keyward/core";
import type { PluginCall } from "@keyward/core";
import { invokeSecret } from "./seal";
import { pluginAct, pluginPlaces } from "./contributions";
import type {
  AccountList,
  AuthenticatorSetup as DaemonAuthenticator,
  EmailTwoFactorSetup as DaemonEmailSetup,
  TwoFactorStatus as DaemonTwoFactor,
  AccountProfile as DaemonProfile,
  KdfInfo as DaemonKdf,
  AppSettings as DaemonSettings,
  LockTimeout as DaemonLockTimeout,
  Catalog as DaemonCatalog,
  ItemDetail as DaemonDetail,
  LoginReply,
  OrgMember,
  SecretField as DaemonField,
  Status,
  TwoFactorProvider as DaemonProvider,
  VaultItem,
  VaultState,
} from "./types";

/// boundary: the daemon's lock timeout as the core's.
function lockTimeoutOf(w: DaemonLockTimeout): LockTimeout {
  const kind = parseLockTimeoutKind(w.kind);
  if (kind !== LockTimeoutKind.Minutes) return { kind };
  if (!("minutes" in w) || !Number.isInteger(w.minutes) || w.minutes <= 0) throw new Error(`the daemon's lock timeout has no minutes: ${JSON.stringify(w)}`);
  return { kind, minutes: w.minutes };
}

/// boundary: the core's lock timeout in the daemon's words.
function wireLockTimeout(v: LockTimeout): DaemonLockTimeout {
  if (v.kind === LockTimeoutKind.Minutes) return { kind: "minutes", minutes: v.minutes };
  return v.kind === LockTimeoutKind.OnRestart ? { kind: "on_restart" } : { kind: "never" };
}

const bool = (v: unknown, what: string): boolean => {
  if (typeof v !== "boolean") throw new Error(`the daemon's setting "${what}" is not a yes or no: ${JSON.stringify(v)}`);
  return v;
};
const seconds = (v: unknown, what: string): number => {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0) throw new Error(`the daemon's setting "${what}" is not a number of seconds: ${JSON.stringify(v)}`);
  return v;
};

/// boundary: the daemon's settings as the core's; a field that does not read
/// stops it, it is never taken for its default.
function settingsOf(w: DaemonSettings): AppSettings {
  if (w.accent_color !== null && (typeof w.accent_color !== "string" || !/^#[0-9a-f]{6}$/i.test(w.accent_color))) throw new Error(`the daemon's accent colour does not read: ${JSON.stringify(w.accent_color)}`);
  return {
    lockTimeout: lockTimeoutOf(w.lock_timeout),
    lockAction: parseLockAction(w.lock_action),
    touchIdOnLaunch: bool(w.touch_id_on_launch, "touch_id_on_launch"),
    touchIdForSecrets: bool(w.touch_id_for_secrets, "touch_id_for_secrets"),
    clipboardClearSeconds: seconds(w.clipboard_clear_seconds, "clipboard_clear_seconds"),
    biometricGraceSeconds: seconds(w.biometric_grace_seconds, "biometric_grace_seconds"),
    showWebsiteIcons: bool(w.show_website_icons, "show_website_icons"),
    hideOnCopy: bool(w.hide_on_copy, "hide_on_copy"),
    keepInTray: bool(w.keep_in_tray, "keep_in_tray"),
    keepInDock: bool(w.keep_in_dock, "keep_in_dock"),
    allowScreenCapture: bool(w.allow_screen_capture, "allow_screen_capture"),
    startOnLogin: bool(w.start_on_login, "start_on_login"),
    theme: parseThemeChoice(w.theme),
    accentColor: w.accent_color,
    language: parseLanguageChoice(w.language),
  };
}

/// A change in the daemon's words, laid over what it holds now: the daemon
/// takes the whole object, and a field the window does not know (the
/// interface) goes back as it came.
function withPatch(w: DaemonSettings, p: SettingsPatch): DaemonSettings {
  const out: DaemonSettings = { ...w };
  if (p.lockTimeout !== undefined) out.lock_timeout = wireLockTimeout(p.lockTimeout);
  if (p.lockAction !== undefined) out.lock_action = p.lockAction;
  if (p.touchIdOnLaunch !== undefined) out.touch_id_on_launch = p.touchIdOnLaunch;
  if (p.touchIdForSecrets !== undefined) out.touch_id_for_secrets = p.touchIdForSecrets;
  if (p.clipboardClearSeconds !== undefined) out.clipboard_clear_seconds = p.clipboardClearSeconds;
  if (p.biometricGraceSeconds !== undefined) out.biometric_grace_seconds = p.biometricGraceSeconds;
  if (p.showWebsiteIcons !== undefined) out.show_website_icons = p.showWebsiteIcons;
  if (p.hideOnCopy !== undefined) out.hide_on_copy = p.hideOnCopy;
  if (p.keepInTray !== undefined) out.keep_in_tray = p.keepInTray;
  if (p.keepInDock !== undefined) out.keep_in_dock = p.keepInDock;
  if (p.allowScreenCapture !== undefined) out.allow_screen_capture = p.allowScreenCapture;
  if (p.startOnLogin !== undefined) out.start_on_login = p.startOnLogin;
  if (p.theme !== undefined) out.theme = p.theme;
  if (p.accentColor !== undefined) out.accent_color = p.accentColor;
  if (p.language !== undefined) out.language = p.language;
  return out;
}

/// What the window says about the sensor (`biometric_state`).
type DaemonBiometric = { available: boolean; problem: string | null; last_failure: string | null };

/// boundary: a typed secret the preview promised; a missing one stops the
/// call rather than sending an empty value.
function typed(secrets: Readonly<Record<string, string>>, id: string): string {
  const v = secrets[id];
  if (v === undefined || v === "") throw new Error(`the preview's field "${id}" was not filled in`);
  return v;
}

/// boundary: the daemon's list of browser extensions; a row that does not
/// read stops it.
function extensionsOf(w: unknown): BrowserExtensions {
  const o = w as { paired?: unknown; pending?: unknown } | null;
  if (!o || !Array.isArray(o.paired) || !Array.isArray(o.pending)) throw new Error("the daemon's list of browser extensions does not read");
  const row = (r: unknown): BrowserExtension => {
    const x = r as Record<string, unknown> | null;
    const ok =
      !!x &&
      typeof x.key === "string" &&
      x.key !== "" &&
      Array.isArray(x.words) &&
      x.words.length > 0 &&
      x.words.every((w) => typeof w === "string") &&
      Number.isInteger(x.at) &&
      Number.isInteger(x.expires);
    if (!ok) throw new Error("a browser extension in the daemon's list does not read");
    return { key: x.key as string, words: [...(x.words as string[])], at: x.at as number, expires: x.expires as number };
  };
  return { paired: o.paired.map(row), pending: o.pending.map(row) };
}

/// boundary: the daemon's derivation as the core's.
function kdfOf(w: DaemonKdf): Kdf {
  const kind = parseKdfKind(w.kind);
  const n = (v: unknown, what: string) => {
    if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) throw new Error(`the daemon's KDF has no ${what}: ${JSON.stringify(w)}`);
    return v;
  };
  if (kind === KdfKind.Pbkdf2) return { kind, iterations: n(w.iterations, "iterations") };
  if (!("memory_mib" in w)) throw new Error(`the daemon's Argon2id has no memory: ${JSON.stringify(w)}`);
  return { kind, iterations: n(w.iterations, "iterations"), memoryMib: n(w.memory_mib, "memory"), parallelism: n(w.parallelism, "parallelism") };
}

/// boundary: the core's derivation in the daemon's words.
function wireKdf(k: Kdf): DaemonKdf {
  return k.kind === KdfKind.Pbkdf2 ? { kind: "pbkdf2", iterations: k.iterations } : { kind: "argon2id", iterations: k.iterations, memory_mib: k.memoryMib, parallelism: k.parallelism };
}

/// boundary: the daemon's profile as the core's.
function profileOf(w: DaemonProfile): AccountProfile {
  if (typeof w.email !== "string" || !Array.isArray(w.fingerprint) || !w.fingerprint.every((x) => typeof x === "string")) throw new Error("the daemon's profile does not read");
  return {
    email: w.email,
    name: w.name,
    hint: w.master_password_hint,
    emailVerified: bool(w.email_verified, "email_verified"),
    premium: bool(w.premium, "premium"),
    created: w.creation_date,
    kdf: kdfOf(w.kdf),
    fingerprint: [...w.fingerprint],
    twoFactor: bool(w.two_factor_enabled, "two_factor_enabled"),
  };
}

/// boundary: the daemon's two-step login as the core's.
function twoFactorOf(w: DaemonTwoFactor): CoreTwoFactorStatus {
  if (!Array.isArray(w.others) || !w.others.every((o) => Number.isInteger(o.provider) && typeof o.name === "string")) throw new Error("the daemon's two-step login does not read");
  return { authenticator: bool(w.authenticator, "authenticator"), email: bool(w.email, "email"), others: w.others.map((o) => ({ provider: o.provider, name: o.name })) };
}

/// A value shown for a moment: dropped, it is let go of.
function held(value: string): Revealed {
  let v: string | null = value;
  return {
    get value() {
      if (v === null) throw new Error("a shown value was read after it was dropped");
      return v;
    },
    drop() {
      v = null;
    },
  };
}

/// boundary: what the window's Rust half saw in front at ⌘⇧L.
function fillContextOf(w: unknown): FillContext {
  const o = w as { app?: unknown; domain?: unknown; field?: { login?: unknown } | null } | null;
  if (!o || typeof o.app !== "string" || (o.domain !== null && o.domain !== undefined && typeof o.domain !== "string")) throw new Error("what was in front at ⌘⇧L does not read");
  return { app: o.app, domain: typeof o.domain === "string" && o.domain !== "" ? o.domain : null, loginPair: !!o.field?.login };
}

/// boundary: a fill's mode in the words of the window's Rust half.
const FILL_WIRE: Record<FillMode, string> = { [FillMode.Both]: "both", [FillMode.Username]: "username", [FillMode.Password]: "password", [FillMode.Totp]: "totp", [FillMode.Card]: "card" };

/// Bitwarden's provider numbers, as the daemon speaks them.
const PROVIDER_ID: Record<TwoFactorProvider, number> = { [TwoFactorProvider.Authenticator]: 0, [TwoFactorProvider.Email]: 1, [TwoFactorProvider.Duo]: 2, [TwoFactorProvider.Yubikey]: 3, [TwoFactorProvider.WebAuthn]: 7, [TwoFactorProvider.Recovery]: 8 };
const PROVIDER_OF = new Map(Object.entries(PROVIDER_ID).map(([k, v]) => [v, k as TwoFactorProvider]));
/// The daemon's answer for "this device is new": a code sent by email.
const NEW_DEVICE = 100;

/// The vault's state as the daemon names it (`keyward_core::vault_state`).
enum DaemonVaultState {
  NeedsSetup = "needs_setup",
  LoggedOut = "logged_out",
  Locked = "locked",
  Unlocked = "unlocked",
  Damaged = "damaged",
  Disabled = "disabled",
}
const parseDaemonVaultState = enumParser(DaemonVaultState, "the daemon's vault state");
type DaemonVault =
  | { state: DaemonVaultState.NeedsSetup }
  | { state: DaemonVaultState.LoggedOut; email: string; server: string }
  | { state: DaemonVaultState.Locked; email: string; server: string }
  | { state: DaemonVaultState.Unlocked; email: string; server: string }
  | { state: DaemonVaultState.Disabled }
  | { state: DaemonVaultState.Damaged; email: string; server: string; reason: string };
/// boundary: the daemon's vault state, its word checked once; the shape is
/// the daemon's own, now under the enum's names.
function vaultOf(v: VaultState): DaemonVault {
  parseDaemonVaultState(v.state);
  return v as unknown as DaemonVault;
}

/// Where the daemon's login stands.
enum DaemonLoginKind {
  Done = "done",
  TwoFactor = "two_factor",
}
const parseDaemonLoginKind = enumParser(DaemonLoginKind, "the daemon's login reply");
type DaemonLogin = { kind: DaemonLoginKind.Done; state: VaultState } | { kind: DaemonLoginKind.TwoFactor; providers: DaemonProvider[] };
/// boundary: the daemon's login reply, its word checked once.
function loginOf(r: LoginReply): DaemonLogin {
  parseDaemonLoginKind(r.kind);
  return r as unknown as DaemonLogin;
}

function session(st: Status): Session {
  const v = vaultOf(st.vault);
  switch (v.state) {
    case DaemonVaultState.NeedsSetup:
      return { state: SessionState.NeedsSetup };
    case DaemonVaultState.LoggedOut:
      return { state: SessionState.LoggedOut, email: v.email, server: v.server };
    case DaemonVaultState.Locked:
      return { state: SessionState.Locked, email: v.email, server: v.server, biometric: st.biometric, pin: st.pin };
    case DaemonVaultState.Unlocked:
      return { state: SessionState.Unlocked, email: v.email, server: v.server, name: null };
    // The saved session does not read: the gate says why and offers to
    // sign in again (the daemon forgets it on `vault_reset_session`).
    case DaemonVaultState.Damaged:
      return { state: SessionState.Damaged, email: v.email, server: v.server, reason: v.reason, canReset: true };
    // The daemon runs on the file source: no vault to open, nothing to
    // reset — the gate says so instead of the window failing to load.
    case DaemonVaultState.Disabled:
      return { state: SessionState.Damaged, email: null, server: null, reason: "err.vaultOff", canReset: false };
  }
}

/// An account's state as the core names it.
function accountState(raw: VaultState): SessionState {
  const v = vaultOf(raw);
  switch (v.state) {
    case DaemonVaultState.NeedsSetup:
      return SessionState.NeedsSetup;
    case DaemonVaultState.LoggedOut:
      return SessionState.LoggedOut;
    case DaemonVaultState.Locked:
      return SessionState.Locked;
    case DaemonVaultState.Unlocked:
      return SessionState.Unlocked;
    case DaemonVaultState.Damaged:
    case DaemonVaultState.Disabled:
      return SessionState.Damaged;
  }
}

function step(raw: LoginReply): LoginStep {
  const r = loginOf(raw);
  if (r.kind === DaemonLoginKind.Done) return { step: LoginStepKind.Done };
  if (r.providers.some((p: DaemonProvider) => p.id === NEW_DEVICE)) return { step: LoginStepKind.NewDevice };
  const providers = r.providers.map((p) => {
    const k = PROVIDER_OF.get(p.id);
    if (!k) throw new Error(`the daemon offered an unknown second factor: ${p.id} (${p.kind})`);
    return k;
  });
  return { step: LoginStepKind.TwoFactor, providers };
}

/// The daemon's words for the core's built-in secret fields.
const DAEMON_FIELD: Record<Exclude<SecretField, SecretField.Custom>, DaemonField> = {
  [SecretField.Password]: "password",
  [SecretField.Username]: "username",
  [SecretField.Totp]: "totp",
  [SecretField.Notes]: "notes",
  [SecretField.CardNumber]: "card_number",
  [SecretField.CardCode]: "card_code",
  [SecretField.PrivateKey]: "private_key",
};
const FIELD_OF = new Map(Object.entries(DAEMON_FIELD).map(([k, v]) => [v as string, k as Exclude<SecretField, SecretField.Custom>]));

function field(ref: SecretRef): DaemonField {
  return ref.field === SecretField.Custom ? { custom: ref.name } : DAEMON_FIELD[ref.field];
}

/// boundary: the daemon's field as the core's reference.
function refOf(itemId: string, f: DaemonField): SecretRef {
  if (typeof f === "object") {
    if ("custom" in f) return { itemId, field: SecretField.Custom, name: f.custom };
    throw new Error("a password-history entry is not an item field");
  }
  const k = FIELD_OF.get(f);
  if (!k) throw new Error(`no secret reference for the daemon's field "${f}"`);
  return { itemId, field: k };
}

const item = (i: VaultItem): Item => ({
  id: i.id,
  name: i.name,
  kind: parseItemKind(i.kind),
  subtitle: i.subtitle,
  folderId: i.folder_id,
  orgId: i.org_id,
  collectionIds: i.collection_ids,
  uris: i.uris,
  tags: i.tags,
  hasTotp: i.has_totp,
  passkeys: i.passkeys,
  favorite: i.favorite,
  deleted: i.deleted,
  reprompt: i.reprompt,
  revised: i.revised ?? null,
  passwordRevised: i.password_revised ?? null,
  expires: i.expires ?? null,
  reused: i.reused ?? 0,
  reuseGroup: i.reuse_group ?? null,
});

/// The daemon's level of a member's collection as the core's, one for one:
/// "edit without passwords" is the core's `editHidden`, so saving a member
/// back neither takes edit rights away nor hands out passwords.
/// boundary: the daemon's words, looked up and refused when unknown.
const PERMISSION_OF: Record<OrgMember["access"][number]["permission"], Permission> = {
  manage: Permission.Manage,
  edit: Permission.Edit,
  edit_hidden: Permission.EditHidden,
  read: Permission.Read,
  read_hidden: Permission.ReadHidden,
};

const memberAccess = (m: OrgMember): Member["access"] => {
  if (m.access_all) return {};
  const out: Member["access"] = {};
  for (const a of m.access) {
    const p = PERMISSION_OF[a.permission];
    if (!p) throw new Error(`the daemon reports an unknown collection permission: ${a.permission}`);
    out[a.id] = p;
  }
  return out;
};

/// The daemon's word for a role or a status it cannot name.
const DAEMON_UNKNOWN = "unknown";
/// boundary: a role the daemon cannot name is the server's own (custom).
const daemonRole = (r: string): OrgRole => (r === DAEMON_UNKNOWN ? OrgRole.Custom : parseOrgRole(r));
/// boundary: a status the daemon cannot name reads as not yet in.
const daemonStatus = (s: string): MemberStatus => (s === DAEMON_UNKNOWN ? MemberStatus.Invited : parseMemberStatus(s));

const member = (orgId: string, m: OrgMember): Member => ({
  id: m.id,
  orgId,
  name: m.name,
  email: m.email,
  role: daemonRole(m.role),
  status: daemonStatus(m.status),
  twoFactor: m.two_factor,
  accessAll: m.access_all,
  access: memberAccess(m),
  isYou: m.is_you,
});

export class DaemonBackend implements Backend {
  readonly caps: Capabilities = { chooseServer: true, accounts: true, biometric: true, plugins: true, clipboardClears: true };
  private readonly listeners = new Set<(c: Change) => void>();
  /// The login waits for the new device's code (the daemon's provider 100)
  /// rather than a second factor's.
  private newDevice = false;
  /// "Add an account": the gate shows an empty sign-in until a login or a
  /// switch, whatever the active account is doing.
  private adding = false;

  /// A change made through the writes, announced like one the daemon made.
  announce(c: Change) {
    this.emit(c);
  }

  private emit(c: Change) {
    for (const l of this.listeners) l(c);
  }
  subscribe(cb: (c: Change) => void) {
    this.listeners.add(cb);
    return () => {
      this.listeners.delete(cb);
    };
  }

  async session(): Promise<Session> {
    const s = session(await invoke<Status>("daemon_status"));
    // Locked elsewhere (idle, the CLI, another window): nothing of the vault
    // is kept here either.
    if (s.state !== SessionState.Unlocked) this.membersChanged();
    return this.adding ? { state: SessionState.NeedsSetup } : s;
  }

  async login(input: { server?: string; identityUrl?: string; email: string; password: string }) {
    if (!input.server) throw new Error("the desktop app needs a server to sign in to");
    await invoke<VaultState>("vault_setup", { baseUrl: input.server, email: input.email, identityUrl: input.identityUrl ?? null });
    // The account now exists and is the active one: the gate follows it.
    this.adding = false;
    const r = step(await invoke<LoginReply>("vault_login", { password: input.password }));
    this.newDevice = r.step === LoginStepKind.NewDevice;
    if (r.step === LoginStepKind.Done) this.emit({ kind: ChangeKind.Session });
    return r;
  }
  async twoFactor(input: { provider: TwoFactorProvider; code: string; remember: boolean }) {
    // "Remember this device": the daemon keeps the server's token sealed in
    // its own store; a new device's code is never remembered.
    const provider = this.newDevice ? NEW_DEVICE : PROVIDER_ID[input.provider];
    const v = await invoke<VaultState>("vault_login_two_factor", { provider, token: input.code, remember: !this.newDevice && input.remember });
    if (vaultOf(v).state !== DaemonVaultState.Unlocked) throw new Error(`the daemon is ${v.state} after the second factor`);
    this.newDevice = false;
    this.emit({ kind: ChangeKind.Session });
    const done: LoginStep = { step: LoginStepKind.Done };
    return done;
  }
  async unlock(password: string) {
    await invoke<VaultState>("vault_unlock", { password });
    this.emit({ kind: ChangeKind.Session });
  }
  /// Touch ID; the daemon asks the system and opens the vault with the key
  /// it keeps in the keychain.
  async unlockBiometric() {
    await invoke<VaultState>("biometric_unlock");
    this.emit({ kind: ChangeKind.Session });
  }
  async unlockPin(pin: string) {
    await invoke<VaultState>("pin_unlock", { pin });
    this.emit({ kind: ChangeKind.Session });
  }
  /// The second factor's email code, or the new device's again: the daemon
  /// knows which one its login waits for.
  async sendTwoFactorCode(_provider: TwoFactorProvider) {
    await invoke("vault_send_two_factor_email");
  }
  async lock() {
    // Members are vault data: not kept past the lock.
    this.membersChanged();
    await invoke("vault_lock");
    this.emit({ kind: ChangeKind.Session });
  }
  async logout() {
    const s = await invoke<{ active: string | null }>("vault_accounts");
    if (!s.active) throw new Error("no account is signed in");
    this.membersChanged();
    await invoke("vault_logout", { id: s.active });
    this.emit({ kind: ChangeKind.Session });
  }
  async sync() {
    await invoke("vault_sync");
    this.membersChanged();
    this.emit({ kind: ChangeKind.Catalog });
  }
  async resetSession() {
    await invoke<VaultState>("vault_reset_session");
    this.emit({ kind: ChangeKind.Session });
  }

  async accounts(): Promise<Account[]> {
    const list = await invoke<AccountList>("vault_accounts");
    return list.accounts.map((a) => ({
      id: a.account.id,
      email: a.account.email,
      server: a.account.base_url,
      // While one is being added, none of them is the one the gate shows.
      active: !this.adding && a.account.id === list.active,
      state: accountState(a.state),
    }));
  }
  async switchAccount(id: string) {
    this.membersChanged();
    await invoke<VaultState>("vault_switch_account", { id });
    this.adding = false;
    this.emit({ kind: ChangeKind.Session });
  }
  async addAccount() {
    this.adding = true;
    this.emit({ kind: ChangeKind.Session });
  }

  // The organisations' members are read apart from the catalogue and kept:
  // the daemon answers them one organisation at a time (about a third of a
  // second each), and the window reloads the catalogue whenever a plugin asks
  // to be asked again — every second and a half during a key check. Read on
  // each reload, they held the vault back for seconds after a touch and piled
  // up in the daemon's queue. They are read again on a sync, a switch, a lock
  // and after a write that changes who reaches what.
  private members: { key: string; list: Member[] } | null = null;
  private membersReading: string | null = null;

  /// Who reaches what changed: the members are read again.
  membersChanged() {
    this.members = null;
    this.membersReading = null;
  }

  private readMembers(orgs: string[], key: string) {
    if (this.membersReading === key) return;
    this.membersReading = key;
    void Promise.all(orgs.map(async (orgId) => (await invoke<OrgMember[]>("org_members", { orgId })).map((m) => member(orgId, m))))
      .then((lists) => {
        if (this.membersReading !== key) return;
        this.members = { key, list: lists.flat() };
        this.emit({ kind: ChangeKind.Catalog });
      })
      .catch((e: unknown) => {
        // Loud, not quiet: the log of actions has the failed command, and the
        // window says so; the next sync or switch tries again.
        if (this.membersReading === key) this.members = { key, list: [] };
        reportError(e);
      })
      .finally(() => {
        if (this.membersReading === key) this.membersReading = null;
      });
  }

  async catalog(): Promise<Catalog> {
    const c = await invoke<DaemonCatalog>("vault_items");
    const managed = c.orgs.filter((o) => o.can.manage_users).map((o) => o.id);
    const key = managed.join(",");
    if (this.members?.key !== key) this.readMembers(managed, key);
    const members = this.members?.key === key ? this.members.list : [];
    return {
      items: c.items.map(item),
      folders: c.folders.map((f) => ({ id: f.id, name: f.name })),
      orgs: c.orgs.map((o) => ({
        id: o.id,
        name: o.name,
        role: daemonRole(o.role),
        can: { editOrg: o.can.edit_org, manageMembers: o.can.manage_users, manageCollections: o.can.create_collections || o.can.edit_collections },
      })),
      collections: c.collections.filter((x) => x.org_id).map((x) => ({ id: x.id, orgId: x.org_id!, name: x.name, readOnly: x.read_only })),
      members,
      // Read after the catalogue: until they come the window shows them on
      // their way (they arrive as a change of the catalogue).
      membersLoading: managed.length > 0 && this.members?.key !== key,
    };
  }

  /// The plugins' places, asked of each plugin on its sealed road. A plugin
  /// that asks to be asked again (a health round filling in) gets the
  /// catalogue reloaded then, and with it its places.
  async contributions() {
    const r = await pluginPlaces();
    clearTimeout(this.placesTimer);
    if (r.refreshMs !== null) this.placesTimer = setTimeout(() => this.emit({ kind: ChangeKind.Catalog }), r.refreshMs);
    return r.contributions;
  }
  private placesTimer: ReturnType<typeof setTimeout> | undefined;

  /// A plugin's verb: its action, then the places again.
  async pluginAct(call: PluginCall) {
    await pluginAct(call);
    this.emit({ kind: ChangeKind.Catalog });
  }

  async item(id: string): Promise<ItemDetail> {
    const [d, c] = await Promise.all([invoke<DaemonDetail>("item_detail", { entryId: id }), invoke<DaemonCatalog>("vault_items")]);
    const summary = c.items.find((i) => i.id === id);
    if (!summary) throw new Error(`item ${id} is not in the catalogue`);
    // The daemon names the note field "note" (crates/vault/src/read.rs).
    const notes = d.fields.find((f) => f.key === "note");
    return {
      item: item(summary),
      fields: d.fields
        .filter((f) => f.key !== "note")
        .map((f) => ({ key: f.key, label: f.label, value: f.secret && f.hidden ? null : f.value, secret: f.secret ? refOf(id, f.secret) : null, mono: f.mono })),
      notes: notes?.secret ? refOf(id, notes.secret) : null,
      passkeys: d.passkeys.map((p) => ({ rpId: p.rp_id, userName: p.user_name })),
      passwordHistory: (d.password_history ?? []).map((h) => ({ changed: h.last_used })),
    };
  }

  /// The daemon answers in how many seconds it clears the clipboard; 0 when
  /// it will not (clearing turned off, a value that is no secret).
  async copy(ref: SecretRef): Promise<Copied> {
    const s = await invoke<number>("copy_secret", { entryId: ref.itemId, field: field(ref) });
    if (!Number.isInteger(s) || s < 0) throw new Error(`the daemon answered a copy with ${String(s)}`);
    return { clearsIn: s > 0 ? s : null };
  }
  async reveal(ref: SecretRef) {
    let value: string | null = await invokeSecret("reveal_secret", { entryId: ref.itemId, field: field(ref) });
    return {
      get value() {
        if (value === null) throw new Error("the revealed value was dropped");
        return value;
      },
      drop: () => {
        value = null;
      },
    };
  }
  async totp(itemId: string): Promise<Totp> {
    const code = await invokeSecret("reveal_secret", { entryId: itemId, field: DAEMON_FIELD[SecretField.Totp] });
    const period = 30;
    return { code, period, remaining: period - (Math.floor(Date.now() / 1000) % period) };
  }

  async trash(ids: string[]) {
    for (const id of ids) await invoke("trash_item", { entryId: id });
    this.emit({ kind: ChangeKind.Catalog });
  }
  async restore(ids: string[]) {
    for (const id of ids) await invoke("restore_item", { entryId: id });
    this.emit({ kind: ChangeKind.Catalog });
  }
  async purge(ids: string[]) {
    await invoke("purge_items", { entryIds: ids });
    this.emit({ kind: ChangeKind.Catalog });
  }

  async settings(): Promise<AppSettings> {
    return settingsOf(await invoke<DaemonSettings>("get_settings"));
  }

  /// Laid over what the daemon holds now; the window's own preferences
  /// (the Dock, the menu bar, screen capture) are put in force at once.
  async setSettings(patch: SettingsPatch): Promise<AppSettings> {
    const now = await invoke<DaemonSettings>("get_settings");
    const saved = await invoke<DaemonSettings>("set_settings", { settings: withPatch(now, patch) });
    await invoke("apply_window_prefs");
    return settingsOf(saved);
  }

  async unlockState(): Promise<UnlockState> {
    const [st, bio] = await Promise.all([invoke<Status>("daemon_status"), invoke<DaemonBiometric>("biometric_state")]);
    if (typeof st.biometric !== "boolean" || typeof st.pin !== "boolean" || typeof bio.available !== "boolean") throw new Error("the daemon's word on Touch ID and the PIN does not read");
    return { biometric: st.biometric, pin: st.pin, biometricProblem: bio.available ? null : (bio.problem ?? "unavailable") };
  }

  /// The master password and the PIN go to the daemon for this one call.
  async account(w: AccountWrite & { secrets: Readonly<Record<string, string>> }): Promise<string | null> {
    const { secrets } = w;
    switch (w.op) {
      case AccountOp.RememberBiometric:
        await invoke("biometric_remember", { password: typed(secrets, "password") });
        return null;
      case AccountOp.ForgetBiometric:
        await invoke("biometric_forget");
        return null;
      case AccountOp.SetPin:
        await invoke("pin_set", { pin: typed(secrets, "pin"), masterPassword: typed(secrets, "password") });
        return null;
      case AccountOp.ClearPin:
        await invoke("pin_clear");
        return null;
      // The daemon writes the export; the window's Rust half asks where to
      // save it and writes a file only its owner can read.
      case AccountOp.Export:
        return await invoke<string | null>("export_vault", { masterPassword: typed(secrets, "password"), format: w.format });
      // The hint goes back as it was: sending none would wipe it.
      case AccountOp.ChangePassword: {
        const { master_password_hint: hint } = await invoke<DaemonProfile>("account_profile");
        await this.afterRelogin(await invoke<LoginReply>("account_change_password", { current: typed(secrets, "current"), new: typed(secrets, "new"), hint }));
        return null;
      }
      case AccountOp.ChangeKdf:
        await this.afterRelogin(await invoke<LoginReply>("account_change_kdf", { masterPassword: typed(secrets, "password"), kdf: wireKdf(w.kdf) }));
        return null;
      case AccountOp.Deauthorize:
        await invoke("account_deauthorize", { masterPassword: typed(secrets, "password") });
        this.emit({ kind: ChangeKind.Session });
        return null;
      case AccountOp.Purge:
        await invoke("account_purge", { masterPassword: typed(secrets, "password") });
        this.emit({ kind: ChangeKind.Catalog });
        return null;
      case AccountOp.DeleteAccount:
        await invoke("account_delete", { masterPassword: typed(secrets, "password") });
        this.emit({ kind: ChangeKind.Session });
        return null;
    }
  }

  /// A change of the master password or its derivation signs in again with
  /// the new one. Where the server asks for the second factor for that, the
  /// account is signed out and the gate takes the person through a sign-in,
  /// as Bitwarden's own clients do after such a change.
  private async afterRelogin(reply: LoginReply) {
    if (step(reply).step !== LoginStepKind.Done) await this.logout();
    else this.emit({ kind: ChangeKind.Session });
  }

  onAutofill(cb: (ctx: FillContext) => void): () => void {
    let off: (() => void) | null = null;
    let gone = false;
    void listen<unknown>("autofill", (e) => {
      try {
        cb(fillContextOf(e.payload));
      } catch (err) {
        console.error(err);
      }
    }).then((un) => {
      if (gone) un();
      else off = un;
    }, console.error);
    return () => {
      gone = true;
      off?.();
    };
  }
  async fill(itemId: string, mode: FillMode): Promise<void> {
    await invoke("autofill_fill", { entryId: itemId, mode: { kind: FILL_WIRE[mode] }, submit: false });
  }
  async fillAccess(): Promise<boolean> {
    return await invoke<boolean>("autofill_trusted");
  }
  async requestFillAccess(): Promise<void> {
    await invoke<boolean>("autofill_request_access");
  }

  async emailChangeCode(password: string, email: string): Promise<void> {
    await invoke("account_email_token", { masterPassword: password, newEmail: email });
  }
  async emailChange(password: string, email: string, code: string): Promise<void> {
    await this.afterRelogin(await invoke<LoginReply>("account_change_email", { masterPassword: password, newEmail: email, token: code }));
  }

  async twoFactorStatus(): Promise<CoreTwoFactorStatus> {
    return twoFactorOf(await invoke<DaemonTwoFactor>("two_factor_status"));
  }
  async authenticatorSetup(password: string): Promise<{ key: Revealed; otpauth: Revealed }> {
    const s = await invoke<DaemonAuthenticator>("two_factor_authenticator_setup", { masterPassword: password });
    if (typeof s.key !== "string" || typeof s.otpauth !== "string" || !s.otpauth.startsWith("otpauth://")) throw new Error("the daemon's authenticator secret does not read");
    return { key: held(s.key), otpauth: held(s.otpauth) };
  }
  async authenticatorEnable(password: string, key: string, code: string): Promise<CoreTwoFactorStatus> {
    return twoFactorOf(await invoke<DaemonTwoFactor>("two_factor_authenticator_enable", { masterPassword: password, key, token: code }));
  }
  async emailTwoFactorSetup(password: string): Promise<{ email: string }> {
    const s = await invoke<DaemonEmailSetup>("two_factor_email_setup", { masterPassword: password });
    if (typeof s.email !== "string") throw new Error("the daemon's email for codes does not read");
    return { email: s.email };
  }
  async emailTwoFactorSend(password: string, email: string): Promise<void> {
    await invoke("two_factor_email_send", { masterPassword: password, email });
  }
  async emailTwoFactorEnable(password: string, email: string, code: string): Promise<CoreTwoFactorStatus> {
    return twoFactorOf(await invoke<DaemonTwoFactor>("two_factor_email_enable", { masterPassword: password, email, token: code }));
  }
  async twoFactorDisable(password: string, provider: number): Promise<CoreTwoFactorStatus> {
    return twoFactorOf(await invoke<DaemonTwoFactor>("two_factor_disable", { masterPassword: password, provider }));
  }
  /// Sealed on its way from the daemon, as every secret the window shows.
  async recoveryCode(password: string): Promise<Revealed> {
    return held(await invokeSecret("two_factor_recovery_code", { masterPassword: password }));
  }

  async profile(): Promise<AccountProfile> {
    return profileOf(await invoke<DaemonProfile>("account_profile"));
  }

  async extensions(): Promise<BrowserExtensions> {
    return extensionsOf(await invoke<unknown>("extensions"));
  }
  /// The daemon asks for the finger itself, the key's words in its prompt.
  async pairExtension(key: string): Promise<BrowserExtensions> {
    return extensionsOf(await invoke<unknown>("extension_pair", { key }));
  }
  async unpairExtension(key: string): Promise<BrowserExtensions> {
    return extensionsOf(await invoke<unknown>("extension_unpair", { key }));
  }

  /// Saved in the settings; the window reloads into the other page.
  async setInterface(ui: InterfaceChoice) {
    await invoke("set_interface", { ui });
  }
}
