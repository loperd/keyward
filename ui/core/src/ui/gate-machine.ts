// The gate's state machine, apart from React so it can be driven in a test:
// which step stands (sign in, a second factor, a new device's code, unlock),
// which action is at work, and what went wrong. It holds no secret: a
// password or a code passes through a call and is not kept; the email and the
// server are what the step shows.
//
//   needsSetup / loggedOut ─ signIn ─┬─ done ──────────────▶ (the app reloads)
//                                    ├─ twoFactor ─ code ──┬─ done
//                                    │      ▲  Esc ▼       └─ newDevice
//                                    └─ newDevice ─ code ── done
//   locked ─ unlock (password | PIN | biometric) ─ done
//   damaged ─ reset (the session is forgotten) ─ loggedOut
//
// Beside every step, where the app holds several accounts: switch to
// another, add one, sign out of this one — each a new session for the app.
//
// Escape goes back one step: a second factor or a device code back to the
// sign-in, an opened server and email back to the remembered pair, a PIN's
// form back to the password's.
import { LoginStepKind, SessionState, TwoFactorProvider, type Account, type Backend, type LoginStep, type Session } from "../backend";
import { isKey, type Args, type Key, type Text } from "../i18n";

/// The providers whose code a person can type; WebAuthn and Duo run a
/// browser flow of their own that the gate does not.
export const TYPABLE: readonly TwoFactorProvider[] = [TwoFactorProvider.Authenticator, TwoFactorProvider.Email, TwoFactorProvider.Yubikey, TwoFactorProvider.Recovery];

/// The step the gate stands at.
export enum GateStep {
  SignIn = "signIn",
  TwoFactor = "twoFactor",
  NewDevice = "newDevice",
  Unlock = "unlock",
  Damaged = "damaged",
}
/// How a locked vault is being opened: by the master password or a PIN.
export enum UnlockMethod {
  Password = "password",
  Pin = "pin",
}
export type GateView =
  | { step: GateStep.SignIn; email: string; server: string; editing: boolean }
  | { step: GateStep.TwoFactor; email: string; server: string; providers: TwoFactorProvider[]; provider: TwoFactorProvider | null; sent: boolean }
  | { step: GateStep.NewDevice; email: string; server: string; sent: boolean }
  | { step: GateStep.Unlock; email: string; server: string; method: UnlockMethod; biometric: boolean; pin: boolean; pinReset: boolean }
  | { step: GateStep.Damaged; email: string | null; server: string | null; reason: Text; canReset: boolean };

/// `opening`: the vault answered and the app is reading it — said apart from
/// the action that got there, so a finished touch never reads as still waiting.
export enum GateAction {
  SignIn = "signIn",
  Code = "code",
  Send = "send",
  Unlock = "unlock",
  Biometric = "biometric",
  Reset = "reset",
  Account = "account",
  Opening = "opening",
}

export type GateState = {
  view: GateView;
  busy: GateAction | null;
  error: Text | null;
  /// The accounts beside this one, where the app holds several; null until
  /// read, or where it holds one.
  accounts: Account[] | null;
  /// The accounts screen stands over the step: a place of its own to switch
  /// to another account, add one or sign out, so the step itself shows only
  /// the account it is for.
  picking: boolean;
};

/// The Bitwarden clouds a person picks by name; anything else is their own
/// server.
export enum Region {
  Us = "us",
  Eu = "eu",
  Self = "self",
}
export const REGIONS = { [Region.Us]: "https://vault.bitwarden.com", [Region.Eu]: "https://vault.bitwarden.eu" } as const;
export function regionOf(server: string): Region {
  const s = normalServer(server);
  if (!s || s === REGIONS.us) return Region.Us;
  if (s === REGIONS.eu) return Region.Eu;
  return Region.Self;
}

/// What the frame around a refusal says, per action.
const FRAME: Record<GateAction, Key> = {
  [GateAction.SignIn]: "gate.signInFailed",
  [GateAction.Code]: "gate.codeFailed",
  [GateAction.Send]: "gate.sendFailed",
  [GateAction.Unlock]: "gate.unlockFailed",
  [GateAction.Biometric]: "gate.biometricFailed",
  [GateAction.Reset]: "gate.resetFailed",
  [GateAction.Account]: "gate.accountFailed", [GateAction.Opening]: "gate.openFailed",
};

/// A daemon's fault as words: `err.code` alone, or `err.code {"name":"value"}`
/// with its values (the shape `keyward_core::fault!` writes). Null when the
/// code is not in the dictionary — then it is not trusted as a key.
export function faultText(msg: string): Text | null {
  const m = /^(err\.[A-Za-z0-9]+)(?: (\{.*\}))?$/s.exec(msg.trim());
  if (!m || !isKey(m[1]!)) return null;
  const key = m[1] as Key;
  if (!m[2]) return { key };
  let raw: unknown;
  try {
    raw = JSON.parse(m[2]);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const args: Args = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v !== "string" && typeof v !== "number") return null;
    args[k] = v;
  }
  return { key, args };
}

/// A refusal in words. The web backend's carries a dictionary code (`err.*`)
/// and is said as it is; the daemon's is a string, a code when it knows the
/// cause, else its own words, shown inside the action's frame.
export function refusal(e: unknown, action: GateAction): Text {
  if (e && typeof e === "object" && "code" in e && typeof e.code === "string" && e.code.startsWith("err.") && isKey(e.code)) {
    const args = "args" in e && e.args && typeof e.args === "object" ? (e.args as Args) : undefined;
    return args ? { key: e.code, args } : { key: e.code };
  }
  const msg = (e instanceof Error ? e.message : String(e)).trim();
  return faultText(msg) ?? { key: FRAME[action], args: { reason: { raw: msg } } };
}

/// What a server field holds, as an origin: a bare host gets https, anything
/// that is not an http(s) URL is refused before it reaches the backend.
export function normalServer(input: string): string | null {
  const s = input.trim().replace(/\/+$/, "");
  if (!s) return null;
  let url: URL;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  if (!url.hostname) return null;
  return (url.origin + url.pathname).replace(/\/+$/, "");
}

export function initialView(s: Exclude<Session, { state: SessionState.Unlocked }>, canPin: boolean): GateView {
  switch (s.state) {
    case SessionState.NeedsSetup:
      return { step: GateStep.SignIn, email: "", server: "", editing: true };
    case SessionState.LoggedOut:
      return { step: GateStep.SignIn, email: s.email ?? "", server: s.server, editing: !s.email };
    case SessionState.Locked: {
      const pin = canPin && s.pin === true;
      return { step: GateStep.Unlock, email: s.email, server: s.server, method: pin ? UnlockMethod.Pin : UnlockMethod.Password, biometric: s.biometric === true, pin, pinReset: false };
    }
    case SessionState.Damaged:
      return { step: GateStep.Damaged, email: s.email, server: s.server, reason: faultText(s.reason) ?? { raw: s.reason }, canReset: s.canReset };
  }
}

export class GateMachine {
  private state: GateState;
  private readonly listeners = new Set<() => void>();
  /// Each step's view gets a number; an answer that comes back after the
  /// person has left that step is not applied to the next one.
  private epoch = 0;
  private autoBiometric = false;
  private autoSent = false;
  private gone = false;

  constructor(
    private readonly backend: Backend,
    session: Exclude<Session, { state: SessionState.Unlocked }>,
    /// Told when the backend let the person in; the app reloads the session.
    private readonly onDone: () => Promise<void> | void = () => {},
  ) {
    this.state = { view: initialView(session, !!backend.unlockPin), busy: null, error: null, accounts: null, picking: false };
  }

  get = (): GateState => this.state;
  subscribe = (cb: () => void): (() => void) => {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  };

  /// Whether the backend offers Touch ID for this account.
  get canBiometric(): boolean {
    const v = this.state.view;
    return this.backend.caps.biometric && !!this.backend.unlockBiometric && v.step === GateStep.Unlock && v.biometric;
  }
  get canSend(): boolean {
    return !!this.backend.sendTwoFactorCode;
  }
  get chooseServer(): boolean {
    return this.backend.caps.chooseServer;
  }
  /// Touch ID is there on this device and not switched on for the account:
  /// said, or its absence looks like a fault.
  get biometricOff(): boolean {
    const v = this.state.view;
    return this.backend.caps.biometric && !!this.backend.unlockBiometric && v.step === GateStep.Unlock && !v.biometric;
  }
  get canAccounts(): boolean {
    return this.backend.caps.accounts && !!this.backend.accounts;
  }
  get canAdd(): boolean {
    return this.canAccounts && !!this.backend.addAccount;
  }
  /// Whether Escape (and the strip's back) has somewhere to go.
  get canBack(): boolean {
    if (this.state.busy) return false;
    if (this.state.picking) return true;
    const v = this.state.view;
    if (v.step === GateStep.TwoFactor || v.step === GateStep.NewDevice) return true;
    if (v.step === GateStep.SignIn) return v.editing && !!v.email;
    if (v.step === GateStep.Unlock) return v.method === UnlockMethod.Pin;
    return false;
  }

  /// The gate is on screen while attached; detached, answers still coming
  /// are dropped. Attaching again (React's strict mode mounts twice) resumes.
  attach(): () => void {
    this.gone = false;
    return () => {
      this.gone = true;
    };
  }

  private set(next: Partial<GateState>) {
    if (this.gone) return;
    this.state = { ...this.state, ...next };
    for (const l of this.listeners) l();
  }
  private move(view: GateView) {
    this.epoch++;
    this.set({ view, error: null, busy: null, picking: false });
  }

  /// One action at a time; its answer is applied only while its step stands.
  private async act(action: GateAction, fn: () => Promise<((v: GateView) => GateView | LoginStepKind.Done) | void>): Promise<void> {
    if (this.state.busy) return;
    const epoch = this.epoch;
    this.set({ busy: action, error: null });
    try {
      const after = await fn();
      if (epoch !== this.epoch || this.gone) return;
      const next = after ? after(this.state.view) : this.state.view;
      if (next === LoginStepKind.Done) {
        // Still at work until the app has the new session: no flash of the
        // form between the answer and the window, and the words say so.
        this.set({ busy: GateAction.Opening });
        await this.onDone();
        this.set({ busy: null });
        return;
      }
      if (next !== this.state.view) {
        this.epoch++;
        this.set({ view: next, busy: null, error: null });
        this.autoSend();
      } else this.set({ busy: null });
    } catch (e) {
      if (epoch !== this.epoch || this.gone) return;
      const error = refusal(e, action);
      const v = this.state.view;
      // The daemon wiped the PIN after five misses: the password's form,
      // with the reason.
      if (v.step === GateStep.Unlock && "key" in error && error.key === "err.pinReset") {
        this.epoch++;
        this.set({ view: { ...v, method: UnlockMethod.Password, pin: false, pinReset: true }, busy: null, error: null });
        return;
      }
      this.set({ busy: null, error });
    }
  }

  private stepTo(r: LoginStep, from: { email: string; server: string }): (v: GateView) => GateView | LoginStepKind.Done {
    return () => {
      if (r.step === LoginStepKind.Done) return LoginStepKind.Done;
      if (r.step === LoginStepKind.NewDevice) return { step: GateStep.NewDevice, email: from.email, server: from.server, sent: true };
      const usable = r.providers.filter((p) => TYPABLE.includes(p));
      return { step: GateStep.TwoFactor, email: from.email, server: from.server, providers: r.providers, provider: usable[0] ?? null, sent: false };
    };
  }

  // --- sign in --------------------------------------------------------------

  /// Opens the server and the email for editing.
  edit() {
    const v = this.state.view;
    if (v.step !== GateStep.SignIn || v.editing || this.state.busy) return;
    this.move({ ...v, editing: true });
  }

  /// `identityUrl`: a self-hosted server's separate identity service, empty
  /// where there is none; taken only where the server is chosen.
  signIn(input: { server: string; identityUrl?: string; email: string; password: string }): Promise<void> {
    const v = this.state.view;
    if (v.step !== GateStep.SignIn) return Promise.resolve();
    const email = input.email.trim();
    let server = v.server;
    let identityUrl: string | null = null;
    if (this.chooseServer) {
      const s = normalServer(input.server);
      if (!s) {
        this.set({ error: { key: "gate.badServer" } });
        return Promise.resolve();
      }
      server = s;
      if (input.identityUrl?.trim()) {
        identityUrl = normalServer(input.identityUrl);
        if (!identityUrl) {
          this.set({ error: { key: "gate.badIdentity" } });
          return Promise.resolve();
        }
      }
    }
    if (!email || !input.password) return Promise.resolve();
    return this.act(GateAction.SignIn, async () => {
      const r = await this.backend.login(
        this.chooseServer ? { server, ...(identityUrl ? { identityUrl } : {}), email, password: input.password } : { email, password: input.password },
      );
      return this.stepTo(r, { email, server });
    });
  }

  // --- a second factor, a new device ----------------------------------------

  choose(provider: TwoFactorProvider) {
    const v = this.state.view;
    if (v.step !== GateStep.TwoFactor || this.state.busy || !TYPABLE.includes(provider) || !v.providers.includes(provider)) return;
    this.move({ ...v, provider, sent: false });
    this.autoSend();
  }

  code(code: string, remember: boolean): Promise<void> {
    const v = this.state.view;
    const c = code.replace(/\s+/g, "");
    if (!c) return Promise.resolve();
    if (v.step === GateStep.TwoFactor) {
      const provider = v.provider;
      if (!provider) return Promise.resolve();
      return this.act(GateAction.Code, async () => this.stepTo(await this.backend.twoFactor({ provider, code: c, remember }), v));
    }
    if (v.step === GateStep.NewDevice) return this.act(GateAction.Code, async () => this.stepTo(await this.backend.twoFactor({ provider: TwoFactorProvider.Email, code: c, remember: false }), v));
    return Promise.resolve();
  }

  send(): Promise<void> {
    const v = this.state.view;
    const send = this.backend.sendTwoFactorCode?.bind(this.backend);
    if (!send) return Promise.resolve();
    if (v.step === GateStep.TwoFactor && v.provider === TwoFactorProvider.Email)
      return this.act(GateAction.Send, async () => {
        await send(TwoFactorProvider.Email);
        return (cur) => (cur.step === GateStep.TwoFactor ? { ...cur, sent: true } : cur);
      });
    if (v.step === GateStep.NewDevice)
      return this.act(GateAction.Send, async () => {
        await send(TwoFactorProvider.Email);
        return (cur) => (cur.step === GateStep.NewDevice ? { ...cur, sent: true } : cur);
      });
    return Promise.resolve();
  }

  /// The email code is asked for once without a press: nobody should have to
  /// press a button for what the step cannot be passed without.
  private autoSend() {
    const v = this.state.view;
    if (this.autoSent || v.step !== GateStep.TwoFactor || v.provider !== TwoFactorProvider.Email || v.sent || !this.canSend) return;
    this.autoSent = true;
    void this.send();
  }

  // --- unlock ---------------------------------------------------------------

  unlock(secret: string): Promise<void> {
    const v = this.state.view;
    if (v.step !== GateStep.Unlock || !secret) return Promise.resolve();
    if (v.method === UnlockMethod.Pin) {
      const byPin = this.backend.unlockPin?.bind(this.backend);
      if (!byPin) throw new Error("the gate offered a PIN the backend cannot take");
      return this.act(GateAction.Unlock, async () => {
        await byPin(secret);
        return () => LoginStepKind.Done;
      });
    }
    return this.act(GateAction.Unlock, async () => {
      await this.backend.unlock(secret);
      return () => LoginStepKind.Done;
    });
  }

  biometric(): Promise<void> {
    const bio = this.backend.unlockBiometric?.bind(this.backend);
    if (!bio || !this.canBiometric) return Promise.resolve();
    return this.act(GateAction.Biometric, async () => {
      await bio();
      return () => LoginStepKind.Done;
    });
  }

  /// Touch ID is asked for once when the locked gate first shows, where it is
  /// set up: a system prompt on every redraw would be a nightmare.
  start() {
    if (this.autoBiometric || !this.canBiometric) return;
    this.autoBiometric = true;
    void this.biometric();
  }

  usePin(on: boolean) {
    const v = this.state.view;
    if (v.step !== GateStep.Unlock || this.state.busy || (on && !v.pin)) return;
    this.move({ ...v, method: on ? UnlockMethod.Pin : UnlockMethod.Password, pinReset: false });
  }

  dismissNotice() {
    const v = this.state.view;
    if (v.step === GateStep.Unlock && v.pinReset) this.set({ view: { ...v, pinReset: false } });
  }

  // --- a damaged session ------------------------------------------------------

  /// Forgets the session that does not read; the app then shows the sign-in.
  reset(): Promise<void> {
    const v = this.state.view;
    const reset = this.backend.resetSession?.bind(this.backend);
    if (v.step !== GateStep.Damaged || !v.canReset) return Promise.resolve();
    if (!reset) throw new Error("the gate offered a reset the backend cannot do");
    return this.act(GateAction.Reset, async () => {
      await reset();
      return () => LoginStepKind.Done;
    });
  }

  /// Reads the session again: the cause may be gone (a keychain that did
  /// not answer, a daemon started on a file).
  retry(): Promise<void> {
    if (this.state.view.step !== GateStep.Damaged) return Promise.resolve();
    return this.act(GateAction.Reset, async () => () => LoginStepKind.Done);
  }

  // --- accounts ---------------------------------------------------------------

  /// Whether the step offers "another account": there is one to switch to,
  /// or one can be added.
  get offersAccounts(): boolean {
    return this.canAccounts && ((this.state.accounts?.some((a) => !a.active) ?? false) || this.canAdd);
  }
  /// Opens the accounts screen over the step; back (Escape) closes it.
  openAccounts(): void {
    if (!this.canAccounts || this.state.busy) return;
    this.set({ picking: true, error: null });
  }

  /// Reads the accounts once the gate shows, where the app holds several.
  loadAccounts(): Promise<void> {
    const list = this.backend.accounts?.bind(this.backend);
    if (!this.canAccounts || !list) return Promise.resolve();
    const epoch = this.epoch;
    return list().then(
      (accounts) => {
        if (!this.gone) this.set({ accounts });
      },
      (e: unknown) => {
        if (!this.gone && epoch === this.epoch) this.set({ error: refusal(e, GateAction.Account) });
      },
    );
  }

  switchTo(id: string): Promise<void> {
    const sw = this.backend.switchAccount?.bind(this.backend);
    const a = this.state.accounts?.find((x) => x.id === id);
    if (!sw || !a || a.active) return Promise.resolve();
    return this.act(GateAction.Account, async () => {
      await sw(id);
      return () => LoginStepKind.Done;
    });
  }

  addAccount(): Promise<void> {
    const add = this.backend.addAccount?.bind(this.backend);
    if (!add || !this.canAdd) return Promise.resolve();
    return this.act(GateAction.Account, async () => {
      await add();
      return () => LoginStepKind.Done;
    });
  }

  /// Signs out of the account the gate stands for; the others stay.
  signOut(): Promise<void> {
    const v = this.state.view;
    if (v.step === GateStep.Damaged || !this.state.accounts?.some((a) => a.active)) return Promise.resolve();
    return this.act(GateAction.Account, async () => {
      await this.backend.logout();
      return () => LoginStepKind.Done;
    });
  }

  // --- back -----------------------------------------------------------------

  /// One step back; false when there is nowhere to go (the key is then the
  /// page's).
  back(): boolean {
    if (this.state.busy) return false;
    if (this.state.picking) {
      this.set({ picking: false, error: null });
      return true;
    }
    const v = this.state.view;
    switch (v.step) {
      case GateStep.TwoFactor:
      case GateStep.NewDevice:
        this.move({ step: GateStep.SignIn, email: v.email, server: v.server, editing: false });
        return true;
      case GateStep.SignIn:
        if (v.editing && v.email) {
          this.move({ ...v, editing: false });
          return true;
        }
        if (this.state.error) {
          this.set({ error: null });
          return true;
        }
        return false;
      case GateStep.Unlock:
        if (v.method === UnlockMethod.Pin) {
          this.move({ ...v, method: UnlockMethod.Password });
          return true;
        }
        if (this.state.error) {
          this.set({ error: null });
          return true;
        }
        return false;
      case GateStep.Damaged:
        if (this.state.error) {
          this.set({ error: null });
          return true;
        }
        return false;
    }
  }
}
