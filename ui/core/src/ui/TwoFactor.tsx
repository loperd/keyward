// Two-step login on the Account page: each method with its state and what
// can be done to it, and the steps of setting one up drawn in place of the
// list. The server asks for the master password on every call, so the step's
// password field stays on screen through the flow, read for each call and
// emptied at its end. The authenticator's secret and the recovery code are
// held in refs, never in React state, drawn while their step stands and
// dropped when it goes; they are read off the screen, never put on the
// clipboard, which nothing would clear.
import { faultWords } from "./fault";
import { useEffect, useRef, useState, type ReactNode } from "react";
import QRCode from "qrcode";
import "./sheet.css";
import { t } from "../i18n";
import type { Revealed } from "../backend";
import { AUTHENTICATOR_PROVIDER, EMAIL_PROVIDER, type TwoFactorStatus } from "../settings/types";
import { SecretInput, type SecretInputHandle } from "./secret-input";
import { Mark, useCore } from "./marks";
import { Icon } from "./Icons";
import { Level } from "../model/types";
import { ToastKind } from "./toasts";

/// Where the panel stands.
enum Step {
  List = "list",
  AuthPassword = "authPassword",
  AuthCode = "authCode",
  EmailPassword = "emailPassword",
  EmailCode = "emailCode",
  RecoveryPassword = "recoveryPassword",
  RecoveryShown = "recoveryShown",
  Disable = "disable",
}
type State = { step: Exclude<Step, Step.Disable> } | { step: Step.Disable; provider: number; name: string };

function Row({ title, hint, on, children }: { title: string; hint?: string; on?: boolean; children: ReactNode }) {
  return (
    <div className="set">
      <span className="set-t">
        <b>{title}</b>
        {hint && <span className="set-h">{hint}</span>}
      </span>
      <span className="set-acts">
        {on !== undefined && <span className={`set-state${on ? " on" : ""}`}>{t(on ? "set.on" : "set.off")}</span>}
        {children}
      </span>
    </div>
  );
}

function SecretRow({ label, handle, onFilled, numeric, autoFocus }: { label: string; handle: React.Ref<SecretInputHandle>; onFilled: (f: boolean) => void; numeric?: boolean; autoFocus?: boolean }) {
  return (
    <div className="frow">
      <span className="fl">
        <span>{label}</span>
      </span>
      <label className="fin">
        <SecretInput ref={handle} onFilled={onFilled} shown={numeric} autoComplete={numeric ? "one-time-code" : "current-password"} {...(numeric ? { inputMode: "numeric" as const } : {})} autoFocus={autoFocus} aria-label={label} />
      </label>
    </div>
  );
}

export function TwoFactorPanel() {
  const core = useCore();
  const b = core.backend;
  const [status, setStatus] = useState<TwoFactorStatus | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [st, setSt] = useState<State>({ step: Step.List });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filled, setFilled] = useState({ password: false, code: false });
  const [address, setAddress] = useState("");
  const [, redraw] = useState(0);
  const password = useRef<SecretInputHandle>(null);
  const code = useRef<SecretInputHandle>(null);
  // What the server handed out for this step: dropped when the step goes.
  const secret = useRef<{ key: Revealed; otpauth: Revealed } | null>(null);
  const recovery = useRef<Revealed | null>(null);
  const qr = useRef<string | null>(null);

  useEffect(() => {
    if (!b.twoFactorStatus) return;
    let live = true;
    b.twoFactorStatus().then(
      (s) => live && setStatus(s),
      (e: unknown) => live && setFailed(faultWords(e)),
    );
    return () => {
      live = false;
    };
  }, [b]);
  const drop = () => {
    secret.current?.key.drop();
    secret.current?.otpauth.drop();
    secret.current = null;
    recovery.current?.drop();
    recovery.current = null;
    qr.current = null;
  };
  useEffect(() => drop, []);

  const go = (next: State) => {
    if (next.step === Step.List) {
      drop();
      password.current?.clear();
      code.current?.clear();
    }
    setError(null);
    // The password field stays through a flow, filled; only the list empties it.
    setFilled((f) => (next.step === Step.List ? { password: false, code: false } : { ...f, code: false }));
    setSt(next);
  };
  const run = (work: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    work()
      .catch((e: unknown) => setError(faultWords(e)))
      .finally(() => setBusy(false));
  };
  const finish = (s: TwoFactorStatus, words: string) => {
    setStatus(s);
    core.toast(ToastKind.Ok, words);
    go({ step: Step.List });
  };
  const read = () => {
    const p = password.current?.read() ?? "";
    if (p === "") throw new Error(t("verb.acct.empty"));
    return p;
  };

  if (failed) return <Mark level={Level.Critical} words={t("tf.failed", { reason: failed })} />;
  if (!status)
    return (
      <div className="set set-wait" role="status" aria-label={t("set.loading")}>
        <span className="set-t">
          <b>{t("set.loading")}</b>
        </span>
      </div>
    );

  if (st.step === Step.List)
    return (
      <>
        <p className="set-h tf-lede">{t("tf.hint")}</p>
        <Row title={t("tf.authenticator")} hint={t("tf.authenticatorHint")} on={status.authenticator}>
          {status.authenticator ? (
            <button type="button" className="btn quiet" onClick={() => go({ step: Step.Disable, provider: AUTHENTICATOR_PROVIDER, name: t("tf.authenticator") })}>
              {t("tf.turnOff")}
            </button>
          ) : (
            <button type="button" className="btn solid" onClick={() => go({ step: Step.AuthPassword })}>
              <Icon name="key" />
              {t("tf.setUp")}
            </button>
          )}
        </Row>
        <Row title={t("tf.email")} hint={t("tf.emailHint")} on={status.email}>
          {status.email ? (
            <button type="button" className="btn quiet" onClick={() => go({ step: Step.Disable, provider: EMAIL_PROVIDER, name: t("tf.email") })}>
              {t("tf.turnOff")}
            </button>
          ) : (
            <button type="button" className="btn quiet" onClick={() => go({ step: Step.EmailPassword })}>
              <Icon name="mail" />
              {t("tf.setUp")}
            </button>
          )}
        </Row>
        {status.others.map((o) => (
          <Row key={o.provider} title={o.name} hint={t("tf.elsewhere")} on>
            <button type="button" className="btn quiet" onClick={() => go({ step: Step.Disable, provider: o.provider, name: o.name })}>
              {t("tf.turnOff")}
            </button>
          </Row>
        ))}
        <Row title={t("tf.recovery")} hint={t("tf.recoveryHint")}>
          <button type="button" className="btn quiet" onClick={() => go({ step: Step.RecoveryPassword })}>
            <Icon name="eye" />
            {t("tf.show")}
          </button>
        </Row>
      </>
    );

  // The steps: a title, what is asked, one action and a way back.
  let title = "";
  let body: ReactNode = null;
  let action: { label: string; ready: boolean; danger?: boolean; run: () => void } | null = null;
  const passwordRow = <SecretRow label={t("tf.password")} handle={password} onFilled={(f) => setFilled((x) => ({ ...x, password: f }))} autoFocus />;
  const codeRow = (label: string) => <SecretRow label={label} handle={code} onFilled={(f) => setFilled((x) => ({ ...x, code: f }))} numeric autoFocus />;

  if (st.step === Step.AuthPassword || st.step === Step.AuthCode) {
    title = t("tf.authenticator");
    const s = secret.current;
    body = (
      <>
        {passwordRow}
        {st.step === Step.AuthCode && s && (
          <>
            <p className="set-h">{t("tf.scan")}</p>
            <div className="tf-qr">
              {qr.current && <img src={qr.current} alt={t("tf.qrAlt")} width={176} height={176} />}
              <span className="tf-key">
                <span className="set-h">{t("tf.key")}</span>
                <code>{s.key.value}</code>
              </span>
            </div>
            {codeRow(t("tf.code"))}
          </>
        )}
      </>
    );
    action =
      st.step === Step.AuthPassword
        ? {
            label: t("tf.next"),
            ready: filled.password,
            run: () =>
              run(async () => {
                if (!b.authenticatorSetup) throw new Error("this app cannot set up an authenticator");
                const got = await b.authenticatorSetup(read());
                secret.current = got;
                qr.current = await QRCode.toDataURL(got.otpauth.value, { margin: 1, width: 176, color: { dark: "#000000ff", light: "#ffffffff" } });
                go({ step: Step.AuthCode });
                redraw((n) => n + 1);
              }),
          }
        : {
            label: t("tf.enable"),
            ready: filled.password && filled.code,
            run: () =>
              run(async () => {
                if (!b.authenticatorEnable || !secret.current) throw new Error("the authenticator's secret is gone");
                const s = await b.authenticatorEnable(read(), secret.current.key.value, code.current!.take());
                password.current?.take();
                finish(s, t("tf.enabled"));
              }),
          };
  } else if (st.step === Step.EmailPassword || st.step === Step.EmailCode) {
    title = t("tf.email");
    body = (
      <>
        {passwordRow}
        <div className="frow">
          <span className="fl">
            <span>{t("tf.address")}</span>
          </span>
          <label className="fin">
            <input type="email" value={address} onChange={(e) => setAddress(e.target.value)} spellCheck={false} autoComplete="email" aria-label={t("tf.address")} disabled={st.step === Step.EmailCode} />
          </label>
        </div>
        {st.step === Step.EmailCode && (
          <>
            <p className="set-h">{t("tf.sent", { email: address })}</p>
            {codeRow(t("tf.emailCode"))}
          </>
        )}
      </>
    );
    action =
      st.step === Step.EmailPassword
        ? {
            label: t("tf.send"),
            ready: filled.password,
            run: () =>
              run(async () => {
                if (!b.emailTwoFactorSetup || !b.emailTwoFactorSend) throw new Error("this app cannot set up email codes");
                const pass = read();
                const to = address.trim() || (await b.emailTwoFactorSetup(pass)).email;
                await b.emailTwoFactorSend(pass, to);
                setAddress(to);
                go({ step: Step.EmailCode });
              }),
          }
        : {
            label: t("tf.enable"),
            ready: filled.password && filled.code,
            run: () =>
              run(async () => {
                if (!b.emailTwoFactorEnable) throw new Error("this app cannot set up email codes");
                const s = await b.emailTwoFactorEnable(read(), address.trim(), code.current!.take());
                password.current?.take();
                finish(s, t("tf.enabled"));
              }),
          };
  } else if (st.step === Step.RecoveryPassword || st.step === Step.RecoveryShown) {
    title = t("tf.recovery");
    const r = recovery.current;
    body =
      st.step === Step.RecoveryShown && r ? (
        <>
          <p className="set-h">{t("tf.recoveryShown")}</p>
          <span className="tf-key">
            <code>{r.value}</code>
          </span>
        </>
      ) : (
        <>
          <p className="set-h">{t("tf.recoveryBody")}</p>
          {passwordRow}
        </>
      );
    action =
      st.step === Step.RecoveryPassword
        ? {
            label: t("tf.show"),
            ready: filled.password,
            run: () =>
              run(async () => {
                if (!b.recoveryCode) throw new Error("this app cannot show the recovery code");
                recovery.current = await b.recoveryCode(password.current!.take());
                go({ step: Step.RecoveryShown });
              }),
          }
        : { label: t("tf.done"), ready: true, run: () => go({ step: Step.List }) };
  } else if (st.step === Step.Disable) {
    title = t("tf.turnOff");
    const s = st;
    body = (
      <>
        <p className="set-h">{t("tf.disableBody", { name: s.name })}</p>
        {passwordRow}
      </>
    );
    action = {
      label: t("tf.turnOff"),
      ready: filled.password,
      danger: true,
      run: () =>
        run(async () => {
          if (!b.twoFactorDisable) throw new Error("this app cannot turn two-step login off");
          finish(await b.twoFactorDisable(password.current!.take(), s.provider), t("tf.disabled"));
        }),
    };
  }
  return (
    <section className="form tf-step" aria-busy={busy || undefined}>
      <h3 className="tf-title">{title}</h3>
      {body}
      {error && (
        <div role="alert">
          <Mark level={Level.Critical} words={error} />
        </div>
      )}
      <div className="vbar">
        {action && (
          <button type="button" className={`btn solid${action.danger ? " danger" : ""}`} disabled={busy || !action.ready} onClick={action.run}>
            {action.label}
          </button>
        )}
        {st.step !== Step.RecoveryShown && (
          <button type="button" className="btn quiet" onClick={() => go({ step: Step.List })} disabled={busy}>
            {t("tf.cancel")}
          </button>
        )}
      </div>
    </section>
  );
}

/// Where a change of email stands.
enum EmailStep {
  Idle = "idle",
  Ask = "ask",
  Code = "code",
}

/// The account's email in the Sign-in section: changing it takes the master
/// password and the new address, a code sent there, and signs in again.
export function EmailChange() {
  const core = useCore();
  const b = core.backend;
  const [step, setStep] = useState(EmailStep.Idle);
  const [address, setAddress] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filled, setFilled] = useState({ password: false, code: false });
  const password = useRef<SecretInputHandle>(null);
  const code = useRef<SecretInputHandle>(null);
  if (!b.emailChangeCode || !b.emailChange) return null;
  const close = () => {
    password.current?.clear();
    code.current?.clear();
    setStep(EmailStep.Idle);
    setError(null);
    setFilled({ password: false, code: false });
  };
  const run = (work: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    work()
      .catch((e: unknown) => setError(faultWords(e)))
      .finally(() => setBusy(false));
  };
  if (step === EmailStep.Idle)
    return (
      <Row title={t("em.title")} hint={t("em.hint")}>
        <button type="button" className="btn quiet" onClick={() => setStep(EmailStep.Ask)}>
          <Icon name="mail" />
          {t("set.change")}
        </button>
      </Row>
    );
  const to = address.trim();
  return (
    <section className="form tf-step" aria-busy={busy || undefined}>
      <h3 className="tf-title">{t("em.title")}</h3>
      <SecretRow label={t("tf.password")} handle={password} onFilled={(f) => setFilled((x) => ({ ...x, password: f }))} autoFocus />
      <div className="frow">
        <span className="fl">
          <span>{t("em.new")}</span>
        </span>
        <label className="fin">
          <input type="email" value={address} onChange={(e) => setAddress(e.target.value)} spellCheck={false} autoComplete="email" aria-label={t("em.new")} disabled={step === EmailStep.Code} />
        </label>
      </div>
      {step === EmailStep.Code && (
        <>
          <p className="set-h">{t("tf.sent", { email: to })}</p>
          <SecretRow label={t("tf.emailCode")} handle={code} onFilled={(f) => setFilled((x) => ({ ...x, code: f }))} numeric autoFocus />
          <p className="set-h">{t("em.relogin")}</p>
        </>
      )}
      {error && (
        <div role="alert">
          <Mark level={Level.Critical} words={error} />
        </div>
      )}
      <div className="vbar">
        {step === EmailStep.Ask ? (
          <button
            type="button"
            className="btn solid"
            disabled={busy || !filled.password || !/^[^@\s]+@[^@\s]+$/.test(to)}
            onClick={() =>
              run(async () => {
                await b.emailChangeCode!(password.current!.read(), to);
                setStep(EmailStep.Code);
              })
            }
          >
            {t("tf.send")}
          </button>
        ) : (
          <button
            type="button"
            className="btn solid"
            disabled={busy || !filled.password || !filled.code}
            onClick={() =>
              run(async () => {
                await b.emailChange!(password.current!.read(), to, code.current!.take());
                password.current?.take();
                core.toast(ToastKind.Ok, t("em.changed", { email: to }));
                close();
              })
            }
          >
            {t("em.go")}
          </button>
        )}
        <button type="button" className="btn quiet" onClick={close} disabled={busy}>
          {t("tf.cancel")}
        </button>
      </div>
    </section>
  );
}
