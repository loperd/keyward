// The gate: what stands before the window while the vault is not open —
// sign in (the server only where the app lets a person choose one), a second
// factor, a new device's code, unlock, a session that does not read; beside
// them the other accounts, where the app holds several. It is the window's
// first sheet: the strip with its path, then one calm column on the sheet,
// at the document's gutter. It is driven by the backend alone through
// GateMachine; a password lives in its field (uncontrolled, never in React
// state nor in the DOM's value attribute) until the press that sends it,
// which empties the field; it is never kept in the machine.
import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type FormEvent, type ReactNode, type Ref } from "react";
import "./gate.css";
import { type Account, type Backend, type Session, TwoFactorProvider, SessionState } from "../backend";
import { currentLang, setLang, t, text, type Key, Lang } from "../i18n";
import { initials } from "../map/model";
import { GateMachine, REGIONS, regionOf, TYPABLE, type GateState, type GateView, Region, GateStep, GateAction, UnlockMethod } from "./gate-machine";
import { Icon } from "./Icons";
import { IconButton, Kbd, Mark, useLang } from "./marks";
import { SecretInput, type SecretInputHandle } from "./secret-input";
import { isDark } from "./Strip";
import { Level } from "../model/types";

export type GateProps = {
  backend: Backend;
  session: Exclude<Session, { state: SessionState.Unlocked }>;
  /// The backend let the person in: the app reads the session again.
  onDone: () => Promise<void> | void;
  /// Whether the locked gate asks for Touch ID by itself (default yes); the
  /// stand turns it off so the gate can be pictured.
  autoBiometric?: boolean;
};

const host = (server: string) => server.replace(/^https?:\/\//, "");

const PROVIDER_NAME: Record<TwoFactorProvider, Key> = {
  [TwoFactorProvider.Authenticator]: "gate.provider.authenticator",
  [TwoFactorProvider.Email]: "gate.provider.email",
  [TwoFactorProvider.Yubikey]: "gate.provider.yubikey",
  [TwoFactorProvider.Recovery]: "gate.provider.recovery",
  [TwoFactorProvider.WebAuthn]: "gate.provider.webauthn",
  [TwoFactorProvider.Duo]: "gate.provider.duo",
};
const PROVIDER_PROMPT: Partial<Record<TwoFactorProvider, Key>> = {
  [TwoFactorProvider.Authenticator]: "gate.prompt.authenticator",
  [TwoFactorProvider.Email]: "gate.prompt.email",
  [TwoFactorProvider.Yubikey]: "gate.prompt.yubikey",
  [TwoFactorProvider.Recovery]: "gate.prompt.recovery",
};
const STATE_WORD: Record<Account["state"], Key> = {
  [SessionState.Locked]: "gate.state.locked",
  [SessionState.Unlocked]: "gate.state.unlocked",
  [SessionState.LoggedOut]: "gate.state.loggedOut",
  [SessionState.NeedsSetup]: "gate.state.needsSetup",
  [SessionState.Damaged]: "gate.state.damaged",
};
/// The last crumb of the strip's path: where in the gate one stands.
const STEP_CRUMB: Record<GateView["step"], { icon: string; key: Key }> = {
  [GateStep.SignIn]: { icon: "user2", key: "gate.path.signIn" },
  [GateStep.TwoFactor]: { icon: "key", key: "gate.twoFactor.title" },
  [GateStep.NewDevice]: { icon: "mail", key: "gate.newDevice.title" },
  [GateStep.Unlock]: { icon: "lock", key: "gate.path.unlock" },
  [GateStep.Damaged]: { icon: "state", key: "gate.path.damaged" },
};

/// An account's mark: the initials of an email's name part.
const markOf = (email: string) => initials(email.split("@")[0]!.replace(/[._+-]+/g, " ")) || "?";

const who = (v: GateView): { email: string | null; server: string | null } => ({ email: v.email || null, server: v.server || null });

export function Gate({ backend, session, onDone, autoBiometric = true }: GateProps) {
  useLang();
  // One machine per session the gate opened on: another state, or another
  // account in the same state (a switch), is a new machine.
  const id = `${session.state}:${"email" in session ? session.email : ""}:${"server" in session ? session.server : ""}`;
  const machine = useMemo(() => new GateMachine(backend, session, onDone), [backend, id]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => machine.attach(), [machine]);
  const state = useSyncExternalStore(machine.subscribe, machine.get);
  useEffect(() => {
    void machine.loadAccounts();
  }, [machine]);
  useEffect(() => {
    if (autoBiometric) machine.start();
  }, [machine, autoBiometric]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && machine.back()) e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [machine]);

  const v = state.view;
  const formKey = `${v.step}:${"editing" in v ? v.editing : ""}:${"method" in v ? v.method : ""}:${"provider" in v ? v.provider : ""}`;
  return (
    <div className="kw-gate">
      <GateStrip m={machine} s={state} />
      <main className="kw-gate-stage">
        <div className="kw-gate-sheet">
          <div className="kw-gate-doc">
            {state.picking ? (
              <Accounts m={machine} s={state} />
            ) : (
              <>
                {v.step === GateStep.SignIn && <SignIn key={formKey} m={machine} s={state} v={v} />}
                {v.step === GateStep.TwoFactor && <TwoFactor key={formKey} m={machine} s={state} v={v} />}
                {v.step === GateStep.NewDevice && <NewDevice key={formKey} m={machine} s={state} v={v} />}
                {v.step === GateStep.Unlock && <Unlock key={formKey} m={machine} s={state} v={v} />}
                {v.step === GateStep.Damaged && <Damaged m={machine} s={state} v={v} />}
                {(v.step === GateStep.Unlock || v.step === GateStep.SignIn) && machine.offersAccounts && (
                  <button type="button" className="kw-btn kw-quiet kw-gate-other" onClick={() => machine.openAccounts()} disabled={state.busy !== null}>
                    <Icon name="people" />
                    <span>{t("gate.account.other")}</span>
                  </button>
                )}
              </>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

/// The window's strip, as it will stand once the vault opens: the blank for
/// the window's buttons, back and forward, the path, then the language, the
/// theme and the account.
function GateStrip({ m, s }: { m: GateMachine; s: GateState }) {
  const [dark, setDark] = useState(isDark);
  const lang = currentLang();
  const v = s.view;
  const crumb = s.picking ? { icon: "people", key: "gate.accounts" as Key } : STEP_CRUMB[v.step];
  const { email, server } = who(v);
  return (
    <header className="kw-strip kw-gate-strip" data-tauri-drag-region="deep">
      <div className="kw-nav">
        <IconButton icon="back" tip={`${t("back")} Esc`} onClick={() => m.back()} disabled={!m.canBack} />
        <IconButton icon="fwd" tip={t("forward")} disabled />
      </div>
      <div className="kw-qline kw-gate-line" aria-label={t("gate.path.signIn")}>
        <span className="kw-crumbs">
          <span className="kw-crumb">
            <Icon name="vault" />
            <span>{t("root")}</span>
          </span>
          <span className="kw-sep">›</span>
          <span className="kw-crumb kw-last">
            <Icon name={crumb.icon} />
            <span>{t(crumb.key)}</span>
          </span>
        </span>
        <span className="kw-gate-line-fill" />
        {server && <span className="kw-qmeta">{host(server)}</span>}
      </div>
      <IconButton icon="lang" tip={lang === Lang.Ru ? t("ui.lang.en") : t("ui.lang.ru")} onClick={() => setLang(lang === Lang.Ru ? Lang.En : Lang.Ru)} />
      <IconButton
        icon={dark ? "sun" : "moon"}
        tip={t("theme")}
        onClick={() => {
          document.documentElement.dataset.theme = dark ? "light" : "dark";
          setDark(!dark);
        }}
      />
      {email && (
        <span className="kw-gate-me kw-tip-l" data-tip={server ? `${email} · ${host(server)}` : email} aria-label={email}>
          <span className="kw-ava">{markOf(email)}</span>
        </span>
      )}
    </header>
  );
}

type StepProps<S extends GateView["step"]> = { m: GateMachine; s: GateState; v: Extract<GateView, { step: S }> };

/// One step: a title and who it is for, then the rows — a label in the
/// document's label column, one 32px control beside it.
function Form({ title, sub, onSubmit, busy, children }: { title: string; sub?: ReactNode; onSubmit: () => void; busy: boolean; children: ReactNode }) {
  return (
    <form
      className="kw-gate-form"
      aria-busy={busy}
      noValidate
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        onSubmit();
      }}
    >
      <div className="kw-gate-head">
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
      <div className="kw-gate-rows">{children}</div>
    </form>
  );
}

/// A row: its words in the label column, the control in the value column.
/// No words: the control stands in the value column alone (actions, notes).
/// `group`: the control is a set of buttons, not a field a label may focus.
/// `text`: a line of words, as tall as its text rather than a control.
function Row({ label, children, group, text: words }: { label?: string; children: ReactNode; group?: boolean; text?: boolean }) {
  const cls = words ? "kw-gate-row kw-text" : "kw-gate-row";
  if (!label)
    return (
      <div className={cls}>
        <span />
        <div className="kw-gate-val">{children}</div>
      </div>
    );
  if (group)
    return (
      <div className={cls} role="group" aria-label={label}>
        <span className="kw-gate-lbl">{label}</span>
        <span className="kw-gate-val">{children}</span>
      </div>
    );
  return (
    <label className={cls}>
      <span className="kw-gate-lbl">{label}</span>
      <span className="kw-gate-val">{children}</span>
    </label>
  );
}

function Secret({ handle, onFilled, label, disabled, autoFocus, numeric }: { handle: Ref<SecretInputHandle>; onFilled: (filled: boolean) => void; label: string; disabled: boolean; autoFocus: boolean; numeric?: boolean }) {
  const [shown, setShown] = useState(false);
  return (
    <Row label={label}>
      <span className="kw-gin kw-gin-secret">
        <SecretInput
          ref={handle}
          onFilled={onFilled}
          shown={shown}
          autoComplete={numeric ? "off" : "current-password"}
          {...(numeric ? { inputMode: "numeric" as const } : {})}
          autoFocus={autoFocus}
          disabled={disabled}
        />
        <IconButton icon="eye" className={shown ? "kw-on kw-tip-l" : "kw-tip-l"} tip={shown ? t("gate.hidePassword") : t("gate.showPassword")} onClick={() => setShown(!shown)} />
      </span>
    </Row>
  );
}

function TextInput({ value, onChange, type = "text", placeholder, autoComplete, autoFocus, disabled }: { value: string; onChange: (v: string) => void; type?: "text" | "email" | "url"; placeholder?: string; autoComplete: string; autoFocus: boolean; disabled: boolean }) {
  return (
    <span className="kw-gin">
      <input type={type} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} spellCheck={false} autoCapitalize="off" autoComplete={autoComplete} autoFocus={autoFocus} disabled={disabled} />
    </span>
  );
}

/// What the gate is doing right now, said where the eye is: waiting for a
/// finger, or opening the vault once it was given. A touch must never look
/// like nothing happened.
function Progress({ s }: { s: GateState }) {
  const what = s.busy === GateAction.Biometric ? "gate.progress.touch" : s.busy === GateAction.Opening ? "gate.progress.opening" : s.busy === GateAction.Unlock ? "gate.progress.unlocking" : null;
  if (!what) return null;
  return (
    <Row>
      <div className={`kw-gate-progress kw-gate-progress-${s.busy}`} role="status" aria-live="polite">
        <span className="kw-gate-pulse" aria-hidden="true">
          <Icon name={s.busy === GateAction.Biometric ? "finger" : "lock"} />
        </span>
        <span>{t(what)}</span>
        <span className="kw-gate-bar" aria-hidden="true" />
      </div>
    </Row>
  );
}

function ErrorLine({ s }: { s: GateState }) {
  if (!s.error) return null;
  return (
    <Row>
      <div className="kw-gate-err" role="alert">
        <Mark level={Level.Critical} words={text(s.error)} />
      </div>
    </Row>
  );
}

function Submit({ label, busyLabel, busy, disabled }: { label: Key; busyLabel: Key; busy: boolean; disabled: boolean }) {
  return (
    <button type="submit" className="kw-btn kw-solid kw-gate-go" disabled={disabled}>
      {busy && <span className="kw-gate-spin" aria-hidden="true" />}
      {t(busy ? busyLabel : label)}
      {!busy && <Kbd>↵</Kbd>}
    </button>
  );
}

/// The main action, then the quiet ways out beside it.
function Actions({ children }: { children: ReactNode }) {
  return (
    <Row>
      <div className="kw-gate-acts">{children}</div>
    </Row>
  );
}

function Back({ m, disabled }: { m: GateMachine; disabled: boolean }) {
  return (
    <button type="button" className="kw-btn" onClick={() => m.back()} disabled={disabled}>
      {t("gate.back")}
      <Kbd>Esc</Kbd>
    </button>
  );
}

function Note({ children, faint }: { children: ReactNode; faint?: boolean }) {
  return (
    <Row text>
      <p className={faint ? "kw-gate-note kw-faint" : "kw-gate-note"}>{children}</p>
    </Row>
  );
}

const REGION_ORDER: Region[] = [Region.Us, Region.Eu, Region.Self];
const REGION_WORD: Record<Region, Key> = { [Region.Us]: "gate.region.us", [Region.Eu]: "gate.region.eu", [Region.Self]: "gate.region.self" };

function SignIn({ m, s, v }: StepProps<GateStep.SignIn>) {
  const choose = m.chooseServer;
  const [region, setRegion] = useState<Region>(() => regionOf(v.server));
  const [own, setOwn] = useState(() => (regionOf(v.server) === Region.Self ? v.server : ""));
  const [identity, setIdentity] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [email, setEmail] = useState(v.email);
  const pw = useRef<SecretInputHandle>(null);
  const [hasPassword, setHasPassword] = useState(false);
  const busy = s.busy !== null;
  const server = region === Region.Self ? own : REGIONS[region];
  const ready = hasPassword && (!v.editing || (!!email.trim() && (!choose || !!server.trim())));
  const submit = () => {
    if (busy || !ready || !pw.current) return;
    // The password leaves the field with the press that sends it.
    void m.signIn({ server: v.editing ? server : v.server, identityUrl: v.editing && region === Region.Self ? identity : "", email: v.editing ? email : v.email, password: pw.current.take() });
  };
  const sub = v.editing ? (choose ? t("gate.signIn.ledeChoose") : t("gate.signIn.lede", { server: host(v.server) })) : `${v.email} · ${host(v.server)}`;
  return (
    <Form title={t("gate.signIn.title")} sub={sub} busy={busy} onSubmit={submit}>
      {v.editing && choose && (
        <>
          <Row label={t("gate.server")} group>
            <span className="kw-seg" role="radiogroup" aria-label={t("gate.server")}>
              {REGION_ORDER.map((r) => (
                <button key={r} type="button" role="radio" aria-checked={r === region} className={r === region ? "kw-on" : ""} disabled={busy} onClick={() => setRegion(r)}>
                  {t(REGION_WORD[r])}
                </button>
              ))}
            </span>
          </Row>
          {region === Region.Self && (
            <Row label={t("gate.serverUrl")}>
              <TextInput type="url" value={own} onChange={setOwn} placeholder={t("gate.serverPlaceholder")} autoComplete="url" autoFocus={!own} disabled={busy} />
            </Row>
          )}
          {region === Region.Self && advanced && (
            <Row label={t("gate.identity")}>
              <TextInput type="url" value={identity} onChange={setIdentity} placeholder={t("gate.identityPlaceholder")} autoComplete="off" autoFocus={false} disabled={busy} />
            </Row>
          )}
        </>
      )}
      {v.editing && (
        <Row label={t("gate.email")}>
          <TextInput type="email" value={email} onChange={setEmail} autoComplete="username" autoFocus={(!choose || region !== Region.Self || !!own) && !email} disabled={busy} />
        </Row>
      )}
      <Secret label={t("gate.password")} handle={pw} onFilled={setHasPassword} disabled={busy} autoFocus={!v.editing || (!!email && (!choose || region !== Region.Self || !!own))} />
      <ErrorLine s={s} />
      <Progress s={s} />
      <Actions>
        <Submit label="gate.submit" busyLabel="gate.signingIn" busy={s.busy === GateAction.SignIn} disabled={busy || !ready} />
        {!v.editing && (
          <button type="button" className="kw-btn" onClick={() => m.edit()} disabled={busy}>
            {t(choose ? "gate.change" : "gate.changeEmail")}
          </button>
        )}
        {v.editing && choose && region === Region.Self && (
          <button type="button" className={advanced ? "kw-btn kw-on" : "kw-btn"} aria-expanded={advanced} onClick={() => setAdvanced(!advanced)} disabled={busy}>
            <Icon name="tune" />
            {t("gate.advanced")}
          </button>
        )}
        {v.editing && v.email && <Back m={m} disabled={busy} />}
      </Actions>
    </Form>
  );
}

function TwoFactor({ m, s, v }: StepProps<GateStep.TwoFactor>) {
  const code = useRef<SecretInputHandle>(null);
  const [hasCode, setHasCode] = useState(false);
  const [remember, setRemember] = useState(false);
  const busy = s.busy !== null;
  const usable = v.providers.filter((p) => TYPABLE.includes(p));
  if (!v.provider) {
    return (
      <Form title={t("gate.twoFactor.title")} sub={v.email} busy={false} onSubmit={() => m.back()}>
        <Note>{t("gate.unsupported", { providers: { list: v.providers.map((p) => ({ key: PROVIDER_NAME[p] })) } })}</Note>
        <Actions>
          <Back m={m} disabled={busy} />
        </Actions>
      </Form>
    );
  }
  const provider = v.provider;
  const prompt = PROVIDER_PROMPT[provider];
  return (
    <Form title={t("gate.twoFactor.title")} sub={v.email} busy={busy} onSubmit={() => !busy && hasCode && code.current && void m.code(code.current.take(), remember)}>
      {usable.length > 1 && (
        <Row label={t("gate.method")} group>
          <span className="kw-seg" role="radiogroup" aria-label={t("gate.method")}>
            {usable.map((p) => (
              <button key={p} type="button" role="radio" aria-checked={p === provider} className={p === provider ? "kw-on" : ""} disabled={busy} onClick={() => m.choose(p)}>
                {t(PROVIDER_NAME[p])}
              </button>
            ))}
          </span>
        </Row>
      )}
      <Row label={t("gate.code")}>
        <span className="kw-gin">
          <SecretInput
            ref={code}
            onFilled={setHasCode}
            shown
            className="kw-mono"
            inputMode={provider === TwoFactorProvider.Authenticator || provider === TwoFactorProvider.Email ? "numeric" : "text"}
            autoComplete="one-time-code"
            autoFocus
            disabled={busy}
          />
        </span>
      </Row>
      {prompt && <Note faint>{t(prompt, { email: v.email })}</Note>}
      <Row>
        <label className="kw-gate-check">
          <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} disabled={busy} />
          <span>{t("gate.remember")}</span>
        </label>
      </Row>
      <ErrorLine s={s} />
      <Progress s={s} />
      <Actions>
        <Submit label="gate.verify" busyLabel="gate.verifying" busy={s.busy === GateAction.Code} disabled={busy || !hasCode} />
        {provider === TwoFactorProvider.Email && m.canSend && <SendCode m={m} s={s} sent={v.sent} email={v.email} />}
        <Back m={m} disabled={busy} />
      </Actions>
    </Form>
  );
}

function SendCode({ m, s, sent, email }: { m: GateMachine; s: GateState; sent: boolean; email: string }) {
  return (
    <button type="button" className="kw-btn" onClick={() => void m.send()} disabled={s.busy !== null} data-tip={sent ? t("gate.sent", { email }) : undefined}>
      <Icon name="mail" />
      {t(s.busy === GateAction.Send ? "gate.sending" : sent ? "gate.resend" : "gate.send")}
    </button>
  );
}

function NewDevice({ m, s, v }: StepProps<GateStep.NewDevice>) {
  const code = useRef<SecretInputHandle>(null);
  const [hasCode, setHasCode] = useState(false);
  const busy = s.busy !== null;
  return (
    <Form title={t("gate.newDevice.title")} sub={v.email} busy={busy} onSubmit={() => !busy && hasCode && code.current && void m.code(code.current.take(), false)}>
      <Row label={t("gate.code")}>
        <span className="kw-gin">
          <SecretInput ref={code} onFilled={setHasCode} shown className="kw-mono" inputMode="numeric" autoComplete="one-time-code" autoFocus disabled={busy} />
        </span>
      </Row>
      <Note faint>{t("gate.newDevice.lede", { email: v.email })}</Note>
      <ErrorLine s={s} />
      <Progress s={s} />
      <Actions>
        <Submit label="gate.verify" busyLabel="gate.verifying" busy={s.busy === GateAction.Code} disabled={busy || !hasCode} />
        {m.canSend && <SendCode m={m} s={s} sent={v.sent} email={v.email} />}
        <Back m={m} disabled={busy} />
      </Actions>
    </Form>
  );
}

function Unlock({ m, s, v }: StepProps<GateStep.Unlock>) {
  const secret = useRef<SecretInputHandle>(null);
  const [hasSecret, setHasSecret] = useState(false);
  const busy = s.busy !== null;
  const pin = v.method === UnlockMethod.Pin;
  const submit = () => {
    if (busy || !hasSecret || !secret.current) return;
    void m.unlock(secret.current.take());
  };
  return (
    <Form title={t("gate.unlock.title")} sub={`${v.email} · ${host(v.server)}`} busy={busy} onSubmit={submit}>
      {v.pinReset && (
        <Row>
          <div className="kw-gate-err" role="status">
            <Mark level={Level.Warning} words={t("err.pinReset")} />
          </div>
        </Row>
      )}
      <Secret label={t(pin ? "gate.pin" : "gate.password")} handle={secret} onFilled={setHasSecret} disabled={busy} autoFocus numeric={pin} />
      <ErrorLine s={s} />
      <Progress s={s} />
      <Actions>
        <Submit label="gate.unlock.submit" busyLabel="gate.unlocking" busy={s.busy === GateAction.Unlock} disabled={busy || !hasSecret} />
        {m.canBiometric && (
          <button type="button" className="kw-btn" onClick={() => void m.biometric()} disabled={busy}>
            <Icon name="finger" />
            {t("gate.biometric")}
          </button>
        )}
        {v.pin && (
          <button type="button" className="kw-btn" onClick={() => m.usePin(!pin)} disabled={busy}>
            {t(pin ? "gate.usePassword" : "gate.usePin")}
            {pin && <Kbd>Esc</Kbd>}
          </button>
        )}
      </Actions>
      {m.biometricOff && <Note faint>{t("gate.noBiometric")}</Note>}
    </Form>
  );
}

/// A session that does not read, or a vault switched off: what is wrong, in
/// words, and the way out — never the window's dead end.
function Damaged({ m, s, v }: StepProps<GateStep.Damaged>) {
  const busy = s.busy !== null;
  const sub = v.email ? (v.server ? `${v.email} · ${host(v.server)}` : v.email) : undefined;
  return (
    <Form title={t(v.canReset ? "gate.damaged.title" : "gate.off.title")} sub={sub} busy={busy} onSubmit={() => void (v.canReset ? m.reset() : m.retry())}>
      <Note>{t(v.canReset ? "gate.damaged.lede" : "gate.off.lede")}</Note>
      <Row>
        <div className="kw-gate-err" role="status">
          <Mark level={Level.Warning} words={text(v.reason)} />
        </div>
      </Row>
      <ErrorLine s={s} />
      <Progress s={s} />
      <Actions>
        {v.canReset ? (
          <>
            <Submit label="gate.damaged.reset" busyLabel="gate.signingIn" busy={s.busy === GateAction.Reset} disabled={busy} />
            <button type="button" className="kw-btn" onClick={() => void m.retry()} disabled={busy}>
              <Icon name="refresh" />
              {t("gate.damaged.retry")}
            </button>
          </>
        ) : (
          <Submit label="gate.damaged.retry" busyLabel="gate.damaged.retry" busy={s.busy === GateAction.Reset} disabled={busy} />
        )}
      </Actions>
    </Form>
  );
}

/// The accounts beside this one, as rows in the columns' style: the one the
/// gate stands for with its way out, the others to switch to, then one more.
function Accounts({ m, s }: { m: GateMachine; s: GateState }) {
  const list = s.accounts;
  if (!m.canAccounts || !list || list.length === 0) return null;
  const busy = s.busy !== null;
  return (
    <section className="kw-gate-accounts" aria-label={t("gate.accounts")}>
      <div className="kw-gate-head">
        <h1>{t("gate.accounts")}</h1>
        <p>{t("gate.accounts.hint")}</p>
      </div>
      {s.error && (
        <div className="kw-gate-err" role="alert">
          <Mark level={Level.Critical} words={text(s.error)} />
        </div>
      )}
      {list.map((a) => (
        <div
          key={a.id}
          className={`kw-row kw-two${a.active ? " kw-gate-here" : ""}`}
          role={a.active ? undefined : "button"}
          tabIndex={a.active || busy ? -1 : 0}
          aria-disabled={busy || undefined}
          onClick={() => !a.active && void m.switchTo(a.id)}
          onKeyDown={(e) => {
            if (!a.active && (e.key === "Enter" || e.key === " ")) {
              e.preventDefault();
              void m.switchTo(a.id);
            }
          }}
        >
          <span className="kw-lead">
            <span className="kw-ava">{markOf(a.email)}</span>
          </span>
          <span className="kw-lbl">
            <span className="kw-t">{a.email}</span>
            <span className="kw-s">
              {host(a.server)} · {t(STATE_WORD[a.state])}
            </span>
          </span>
          <span className="kw-side">
            {a.active ? (
              <>
                <span className="kw-n">{t("gate.account.current")}</span>
                <IconButton icon="logout" className="kw-tip-l" tip={t("gate.account.signOut")} onClick={() => void m.signOut()} disabled={busy} />
              </>
            ) : (
              <Icon name="chev" className="kw-faint" />
            )}
          </span>
        </div>
      ))}
      {m.canAdd && (
        <div
          className="kw-row"
          role="button"
          tabIndex={busy ? -1 : 0}
          onClick={() => void m.addAccount()}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              void m.addAccount();
            }
          }}
        >
          <span className="kw-lead">
            <Icon name="plus" />
          </span>
          <span className="kw-lbl">
            <span className="kw-gate-add">{t("gate.account.add")}</span>
          </span>
        </div>
      )}
    </section>
  );
}
