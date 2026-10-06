// The gate's state machine over a fake backend: every step, every way back,
// the refusals in words, and that no password stays behind.
import { describe, expect, it, vi } from "vitest";
import { type Account, type Backend, type Capabilities, type LoginStep, type Session, TwoFactorProvider, LoginStepKind, SessionState } from "../backend";
import { faultText, GateMachine, normalServer, refusal, regionOf, REGIONS, GateAction } from "./gate-machine";

class WebLikeError extends Error {
  constructor(
    readonly code: string,
    readonly args: Record<string, string | number> = {},
  ) {
    super(code);
  }
}

type Calls = { login: unknown[]; twoFactor: unknown[]; unlock: string[]; pin: string[]; bio: number; send: TwoFactorProvider[] };

function fake(opts: {
  caps?: Partial<Capabilities>;
  login?: (i: { server?: string; email: string; password: string }) => Promise<LoginStep>;
  twoFactor?: (i: { provider: TwoFactorProvider; code: string; remember: boolean }) => Promise<LoginStep>;
  unlock?: (p: string) => Promise<void>;
  pin?: boolean;
  biometric?: boolean;
  send?: boolean;
}) {
  const calls: Calls = { login: [], twoFactor: [], unlock: [], pin: [], bio: 0, send: [] };
  const b: Partial<Backend> & { caps: Capabilities } = {
    caps: { chooseServer: false, accounts: false, biometric: false, plugins: false, clipboardClears: true, ...opts.caps },
    login: async (i) => {
      calls.login.push(i);
      return opts.login ? opts.login(i) : { step: LoginStepKind.Done };
    },
    twoFactor: async (i) => {
      calls.twoFactor.push(i);
      return opts.twoFactor ? opts.twoFactor(i) : { step: LoginStepKind.Done };
    },
    unlock: async (p) => {
      calls.unlock.push(p);
      if (opts.unlock) await opts.unlock(p);
    },
  };
  if (opts.pin)
    b.unlockPin = async (p) => {
      calls.pin.push(p);
      if (p === "00000") throw new Error("err.pinReset");
    };
  if (opts.biometric)
    b.unlockBiometric = async () => {
      calls.bio++;
    };
  if (opts.send !== false)
    b.sendTwoFactorCode = async (p) => {
      calls.send.push(p);
    };
  return { backend: b as Backend, calls };
}

const loggedOut: Session = { state: SessionState.LoggedOut, email: "alex@example.com", server: "https://vault.example.com" };
const locked = (extra: Partial<Extract<Session, { state: "locked" }>> = {}): Extract<Session, { state: "locked" }> => ({
  state: SessionState.Locked,
  email: "alex@example.com",
  server: "https://vault.example.com",
  ...extra,
});
const tick = () => new Promise((r) => setTimeout(r, 0));

describe("the gate's sign-in", () => {
  it("starts editing when nothing is known, and on the password when the email is", () => {
    const { backend } = fake({});
    expect(new GateMachine(backend, { state: SessionState.NeedsSetup }).get().view).toMatchObject({ step: "signIn", editing: true, email: "", server: "" });
    expect(new GateMachine(backend, loggedOut).get().view).toMatchObject({ step: "signIn", editing: false, email: "alex@example.com" });
    expect(new GateMachine(backend, { ...loggedOut, email: null }).get().view).toMatchObject({ editing: true });
  });

  it("sends no server where the app has one fixed, and reports done", async () => {
    const { backend, calls } = fake({});
    const done = vi.fn();
    const m = new GateMachine(backend, loggedOut, done);
    await m.signIn({ server: "https://evil.example", email: " alex@example.com ", password: "pw" });
    expect(calls.login).toEqual([{ email: "alex@example.com", password: "pw" }]);
    expect(done).toHaveBeenCalledOnce();
    expect(m.get().busy).toBeNull();
  });

  it("normalises the chosen server and refuses one that does not read", async () => {
    const { backend, calls } = fake({ caps: { chooseServer: true } });
    const m = new GateMachine(backend, { state: SessionState.NeedsSetup });
    await m.signIn({ server: "javascript:alert(1)", email: "a@b.c", password: "pw" });
    expect(calls.login).toEqual([]);
    expect(m.get().error).toEqual({ key: "gate.badServer" });
    await m.signIn({ server: "vault.example.com/", email: "a@b.c", password: "pw" });
    expect(calls.login).toEqual([{ server: "https://vault.example.com", email: "a@b.c", password: "pw" }]);
    expect(normalServer("http://localhost:8080/")).toBe("http://localhost:8080");
    expect(normalServer("")).toBeNull();
  });

  it("is busy while the backend works and takes one action at a time", async () => {
    let release!: () => void;
    const { backend, calls } = fake({ login: () => new Promise((r) => (release = () => r({ step: LoginStepKind.Done }))) });
    const m = new GateMachine(backend, loggedOut);
    const p = m.signIn({ server: "", email: "a@b.c", password: "pw" });
    expect(m.get().busy).toBe("signIn");
    void m.signIn({ server: "", email: "a@b.c", password: "pw" });
    expect(m.back()).toBe(false);
    release();
    await p;
    expect(calls.login).toHaveLength(1);
    expect(m.get().busy).toBeNull();
  });

  it("says a web refusal by its code and a daemon's string inside a frame", async () => {
    const web = fake({ login: () => Promise.reject(new WebLikeError("err.loginRateLimited")) });
    const m = new GateMachine(web.backend, loggedOut);
    await m.signIn({ server: "", email: "a@b.c", password: "pw" });
    expect(m.get().error).toEqual({ key: "err.loginRateLimited", args: {} });
    expect(m.get().view.step).toBe("signIn");

    expect(refusal("err.badCredentials", GateAction.SignIn)).toEqual({ key: "err.badCredentials" });
    expect(refusal(new Error("connection refused (os error 61)"), GateAction.Unlock)).toEqual({ key: "gate.unlockFailed", args: { reason: { raw: "connection refused (os error 61)" } } });
    // A code the dictionary does not have is not trusted as a key.
    expect(refusal(new WebLikeError("err.nope"), GateAction.Code)).toEqual({ key: "gate.codeFailed", args: { reason: { raw: "err.nope" } } });
  });

  it("never keeps the password in its state", async () => {
    const { backend } = fake({ login: () => Promise.reject(new Error("err.badPassword")) });
    const m = new GateMachine(backend, loggedOut);
    await m.signIn({ server: "", email: "a@b.c", password: "hunter2-secret" });
    expect(JSON.stringify(m.get())).not.toContain("hunter2-secret");
  });

  it("edits the remembered pair and goes back to it on Escape", () => {
    const { backend } = fake({});
    const m = new GateMachine(backend, loggedOut);
    m.edit();
    expect(m.get().view).toMatchObject({ editing: true });
    expect(m.back()).toBe(true);
    expect(m.get().view).toMatchObject({ editing: false });
    expect(m.back()).toBe(false);
  });
});

describe("the gate's second factor", () => {
  it("offers the typable providers, sends an email code once by itself, and passes remember", async () => {
    const { backend, calls } = fake({ login: async () => ({ step: LoginStepKind.TwoFactor, providers: [TwoFactorProvider.WebAuthn, TwoFactorProvider.Email, TwoFactorProvider.Authenticator] }) });
    const done = vi.fn();
    const m = new GateMachine(backend, loggedOut, done);
    await m.signIn({ server: "", email: "a@b.c", password: "pw" });
    const v = m.get().view;
    expect(v).toMatchObject({ step: "twoFactor", provider: "email", providers: ["webauthn", "email", "authenticator"] });
    await tick();
    expect(calls.send).toEqual(["email"]);
    expect(m.get().view).toMatchObject({ sent: true });

    m.choose(TwoFactorProvider.WebAuthn);
    expect(m.get().view).toMatchObject({ provider: "email" });
    m.choose(TwoFactorProvider.Authenticator);
    expect(m.get().view).toMatchObject({ provider: "authenticator", sent: false });
    m.choose(TwoFactorProvider.Email);
    await tick();
    expect(calls.send).toEqual(["email"]);

    m.choose(TwoFactorProvider.Authenticator);
    await m.code(" 123 456 ", true);
    expect(calls.twoFactor).toEqual([{ provider: "authenticator", code: "123456", remember: true }]);
    expect(done).toHaveBeenCalledOnce();
  });

  it("has nothing to type when only browser flows are offered", async () => {
    const { backend } = fake({ login: async () => ({ step: LoginStepKind.TwoFactor, providers: [TwoFactorProvider.WebAuthn, TwoFactorProvider.Duo] }) });
    const m = new GateMachine(backend, loggedOut);
    await m.signIn({ server: "", email: "a@b.c", password: "pw" });
    expect(m.get().view).toMatchObject({ step: "twoFactor", provider: null });
    await m.code("123456", false);
    expect(m.get().view.step).toBe("twoFactor");
  });

  it("goes back to the sign-in on Escape, keeping the email", async () => {
    const { backend } = fake({ login: async () => ({ step: LoginStepKind.TwoFactor, providers: [TwoFactorProvider.Authenticator] }) });
    const m = new GateMachine(backend, { state: SessionState.NeedsSetup });
    await m.signIn({ server: "", email: "new@b.c", password: "pw" });
    expect(m.back()).toBe(true);
    expect(m.get().view).toEqual({ step: "signIn", email: "new@b.c", server: "", editing: false });
  });

  it("keeps the step and says why when a code is refused", async () => {
    const { backend } = fake({
      login: async () => ({ step: LoginStepKind.TwoFactor, providers: [TwoFactorProvider.Authenticator] }),
      twoFactor: () => Promise.reject(new WebLikeError("err.badTwoFactor")),
    });
    const m = new GateMachine(backend, loggedOut);
    await m.signIn({ server: "", email: "a@b.c", password: "pw" });
    await m.code("000000", false);
    expect(m.get()).toMatchObject({ view: { step: "twoFactor" }, error: { key: "err.badTwoFactor" }, busy: null });
  });

  it("lets Escape wait for the email code it is sending", async () => {
    let release!: () => void;
    const { backend } = fake({
      login: async () => ({ step: LoginStepKind.TwoFactor, providers: [TwoFactorProvider.Email] }),
    });
    backend.sendTwoFactorCode = () => new Promise((r) => (release = r));
    const m = new GateMachine(backend, loggedOut);
    await m.signIn({ server: "", email: "a@b.c", password: "pw" });
    // the auto-send is at work; Escape waits for it
    expect(m.get().busy).toBe("send");
    expect(m.back()).toBe(false);
    release();
    await tick();
    expect(m.get().view).toMatchObject({ sent: true });
  });
});

describe("the gate's new device", () => {
  it("takes the email's code, resends it, and may follow a second factor", async () => {
    const { backend, calls } = fake({
      login: async () => ({ step: LoginStepKind.TwoFactor, providers: [TwoFactorProvider.Authenticator] }),
      twoFactor: async (i) => (i.code === "111111" ? { step: LoginStepKind.NewDevice } : { step: LoginStepKind.Done }),
    });
    const done = vi.fn();
    const m = new GateMachine(backend, loggedOut, done);
    await m.signIn({ server: "", email: "a@b.c", password: "pw" });
    await m.code("111111", false);
    expect(m.get().view).toMatchObject({ step: "newDevice", sent: true });
    await m.send();
    expect(calls.send).toEqual(["email"]);
    await m.code("222222", true);
    expect(calls.twoFactor.at(-1)).toEqual({ provider: "email", code: "222222", remember: false });
    expect(done).toHaveBeenCalledOnce();
  });
});

describe("the gate's unlock", () => {
  it("unlocks with the password and reports a refusal in its frame", async () => {
    let fail = true;
    const { backend, calls } = fake({ unlock: async () => (fail ? Promise.reject(new Error("bad things")) : undefined) });
    const done = vi.fn();
    const m = new GateMachine(backend, locked(), done);
    await m.unlock("pw");
    expect(m.get().error).toEqual({ key: "gate.unlockFailed", args: { reason: { raw: "bad things" } } });
    expect(m.back()).toBe(true);
    expect(m.get().error).toBeNull();
    fail = false;
    await m.unlock("pw");
    expect(calls.unlock).toEqual(["pw", "pw"]);
    expect(done).toHaveBeenCalledOnce();
  });

  it("offers Touch ID only with the capability, the method and the account's setting, and asks once by itself", async () => {
    const off = fake({ caps: { biometric: false }, biometric: true });
    expect(new GateMachine(off.backend, locked({ biometric: true })).canBiometric).toBe(false);
    const noMethod = fake({ caps: { biometric: true } });
    expect(new GateMachine(noMethod.backend, locked({ biometric: true })).canBiometric).toBe(false);
    const notSet = fake({ caps: { biometric: true }, biometric: true });
    expect(new GateMachine(notSet.backend, locked({ biometric: false })).canBiometric).toBe(false);

    const on = fake({ caps: { biometric: true }, biometric: true });
    const done = vi.fn();
    const m = new GateMachine(on.backend, locked({ biometric: true }), done);
    expect(m.canBiometric).toBe(true);
    m.start();
    m.start();
    await tick();
    expect(on.calls.bio).toBe(1);
    expect(done).toHaveBeenCalledOnce();
  });

  it("starts on the PIN where one is set, falls back to the password on Escape or a reset", async () => {
    const { backend, calls } = fake({ pin: true });
    const m = new GateMachine(backend, locked({ pin: true }));
    expect(m.get().view).toMatchObject({ method: "pin", pin: true });
    expect(m.back()).toBe(true);
    expect(m.get().view).toMatchObject({ method: "password" });
    m.usePin(true);
    await m.unlock("00000");
    expect(calls.pin).toEqual(["00000"]);
    expect(m.get().view).toMatchObject({ method: "password", pin: false, pinReset: true });
    expect(m.get().error).toBeNull();
    m.usePin(true);
    expect(m.get().view).toMatchObject({ method: "password" });
  });

  it("ignores a PIN the backend cannot take", () => {
    const { backend } = fake({});
    expect(new GateMachine(backend, locked({ pin: true })).get().view).toMatchObject({ method: "password", pin: false });
  });
});

describe("the gate's server and identity", () => {
  it("names the Bitwarden clouds and takes anything else as one's own", () => {
    expect(regionOf("")).toBe("us");
    expect(regionOf("https://vault.bitwarden.com/")).toBe("us");
    expect(regionOf("vault.bitwarden.eu")).toBe("eu");
    expect(regionOf("https://vault.example.net")).toBe("self");
  });

  it("passes a separate identity server only when given, and refuses one that does not read", async () => {
    const { backend, calls } = fake({ caps: { chooseServer: true } });
    const m = new GateMachine(backend, { state: SessionState.NeedsSetup });
    await m.signIn({ server: "vault.example.net", identityUrl: "ftp://id", email: "a@b.c", password: "pw" });
    expect(calls.login).toEqual([]);
    expect(m.get().error).toEqual({ key: "gate.badIdentity" });
    await m.signIn({ server: "vault.example.net", identityUrl: "id.example.net/", email: "a@b.c", password: "pw" });
    await m.signIn({ server: REGIONS.eu, identityUrl: "  ", email: "a@b.c", password: "pw" });
    expect(calls.login).toEqual([
      { server: "https://vault.example.net", identityUrl: "https://id.example.net", email: "a@b.c", password: "pw" },
      { server: "https://vault.bitwarden.eu", email: "a@b.c", password: "pw" },
    ]);
  });
});

describe("a daemon's fault in words", () => {
  it("reads a code with its values, and trusts no code the dictionary lacks", () => {
    expect(faultText("err.badPassword")).toEqual({ key: "err.badPassword" });
    expect(faultText('err.sessionKeyUnavailable {"reason":"locked"}')).toEqual({ key: "err.sessionKeyUnavailable", args: { reason: "locked" } });
    expect(faultText('err.nope {"reason":"x"}')).toBeNull();
    expect(faultText('err.sessionKeyUnavailable {"reason":{"key":"root"}}')).toBeNull();
    expect(faultText("err.sessionKeyUnavailable {not json")).toBeNull();
    expect(refusal(new Error('err.sessionKeyUnavailable {"reason":"locked"}'), GateAction.Unlock)).toEqual({ key: "err.sessionKeyUnavailable", args: { reason: "locked" } });
  });
});

describe("the gate on a damaged session", () => {
  const damaged = (canReset: boolean): Extract<Session, { state: "damaged" }> => ({ state: SessionState.Damaged, email: "alex@example.com", server: "https://vault.example.com", reason: "err.sessionTampered", canReset });

  it("says why, and forgets the session at the person's word", async () => {
    const { backend } = fake({});
    let resets = 0;
    backend.resetSession = async () => {
      resets++;
    };
    const done = vi.fn();
    const m = new GateMachine(backend, damaged(true), done);
    expect(m.get().view).toMatchObject({ step: "damaged", reason: { key: "err.sessionTampered" }, canReset: true });
    await m.reset();
    expect(resets).toBe(1);
    expect(done).toHaveBeenCalledOnce();
  });

  it("only reads again where nothing can be reset, and says a refusal", async () => {
    const { backend } = fake({});
    backend.resetSession = () => Promise.reject(new Error("err.sessionNotDamaged"));
    const done = vi.fn();
    const off = new GateMachine(backend, { state: SessionState.Damaged, email: null, server: null, reason: "err.vaultOff", canReset: false }, done);
    await off.reset();
    expect(done).not.toHaveBeenCalled();
    await off.retry();
    expect(done).toHaveBeenCalledOnce();
    const m = new GateMachine(backend, damaged(true), done);
    await m.reset();
    expect(m.get().error).toEqual({ key: "err.sessionNotDamaged" });
    expect(m.back()).toBe(true);
    expect(m.get().error).toBeNull();
  });

  it("shows a reason it cannot read as it came", () => {
    const { backend } = fake({});
    expect(new GateMachine(backend, { ...damaged(true), reason: "something broke" }).get().view).toMatchObject({ reason: { raw: "something broke" } });
  });
});

describe("the gate's accounts", () => {
  const list: Account[] = [
    { id: "a", email: "alex@example.com", server: "https://vault.example.com", active: true, state: SessionState.Locked },
    { id: "b", email: "ops@example.com", server: "https://vault.bitwarden.eu", active: false, state: SessionState.Unlocked },
  ];
  function several() {
    const f = fake({ caps: { accounts: true } });
    const calls: string[] = [];
    f.backend.accounts = async () => list;
    f.backend.switchAccount = async (id) => void calls.push(`switch ${id}`);
    f.backend.addAccount = async () => void calls.push("add");
    f.backend.logout = async () => void calls.push("logout");
    return { ...f, accountCalls: calls };
  }

  it("keeps the step about its own account and opens the others on a screen of their own", async () => {
    const { backend } = several();
    const m = new GateMachine(backend, { state: SessionState.Locked, email: "alex@example.com", server: "https://vault.example.com" }, () => {});
    m.attach();
    await m.loadAccounts();
    expect(m.get().picking).toBe(false);
    expect(m.offersAccounts).toBe(true);
    expect(m.canBack).toBe(false);
    m.openAccounts();
    expect(m.get().picking).toBe(true);
    expect(m.get().view.step).toBe("unlock");
    expect(m.canBack).toBe(true);
    expect(m.back()).toBe(true);
    expect(m.get().picking).toBe(false);
    expect(m.get().view.step).toBe("unlock");
  });

  it("reads nothing where the app holds one account", async () => {
    const { backend } = fake({});
    backend.accounts = () => Promise.reject(new Error("must not be asked"));
    const m = new GateMachine(backend, locked());
    await m.loadAccounts();
    expect(m.canAccounts).toBe(false);
    expect(m.get().accounts).toBeNull();
    expect(m.get().error).toBeNull();
  });

  it("switches to another, adds one, signs out of this one — each a new session", async () => {
    const { backend, accountCalls } = several();
    const done = vi.fn();
    const m = new GateMachine(backend, locked(), done);
    await m.loadAccounts();
    expect(m.get().accounts).toEqual(list);
    await m.switchTo("a");
    expect(accountCalls).toEqual([]);
    await m.switchTo("b");
    await m.addAccount();
    await m.signOut();
    expect(accountCalls).toEqual(["switch b", "add", "logout"]);
    expect(done).toHaveBeenCalledTimes(3);
  });

  it("says when the accounts do not answer", async () => {
    const { backend } = several();
    backend.accounts = () => Promise.reject(new Error("socket closed"));
    const m = new GateMachine(backend, locked());
    await m.loadAccounts();
    expect(m.get().error).toEqual({ key: "gate.accountFailed", args: { reason: { raw: "socket closed" } } });
  });
});

describe("the gate's Touch ID hint", () => {
  it("says Touch ID is off only where the device has it and the account has not", () => {
    const off = fake({ caps: { biometric: true }, biometric: true });
    expect(new GateMachine(off.backend, locked({ biometric: false })).biometricOff).toBe(true);
    expect(new GateMachine(off.backend, locked({ biometric: true })).biometricOff).toBe(false);
    const none = fake({ caps: { biometric: false } });
    expect(new GateMachine(none.backend, locked()).biometricOff).toBe(false);
  });
});
