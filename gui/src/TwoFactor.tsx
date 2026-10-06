import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert } from "./ui";
import { t } from "./i18n";
import type { Key } from "./i18n";
import type { LoginReply, TwoFactorProvider } from "./types";

/// The provider's name in the interface's language; for unfamiliar ones, as
/// the daemon named it.
export function providerName(p: TwoFactorProvider): string {
  const key = `twofactor.provider.${p.id}` as Key;
  return t(key) === key ? p.name : t(key);
}

export function providerPrompt(p: TwoFactorProvider): string {
  const key = `twofactor.prompt.${p.id}` as Key;
  return t(key) === key ? p.prompt : t(key);
}

/// The second-factor step, one for logging in and for account operations
/// alike.
///
/// After a change of password, of email, of KDF, or a deauthorisation, the
/// server resets the tokens, the daemon logs in again and may run into the same
/// second factor as at an ordinary login. There is one screen for it, so that in
/// the settings it looks as it does at the gate rather than different in every
/// modal.
export function TwoFactorForm({
  providers,
  onDone,
  onBack,
  autoSend = true,
}: {
  providers: TwoFactorProvider[];
  /// The daemon took the code and logged in.
  onDone: () => void;
  onBack?: () => void;
  /// Ask for the code by email at once, when that is the first method that
  /// will do.
  autoSend?: boolean;
}) {
  const usable = providers.filter((p) => p.kind !== "unsupported");
  const [chosen, setChosen] = useState<TwoFactorProvider | null>(usable[0] ?? null);
  const [token, setToken] = useState("");
  // The device check's letter went out with the refusal itself.
  const [sent, setSent] = useState(usable[0]?.kind === "new_device");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [asked, setAsked] = useState(false);

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const sendEmail = () =>
    run(async () => {
      await invoke("vault_send_two_factor_email");
      setSent(true);
    });

  // The code by email is asked for once by us: nobody should have to press a
  // button to get what the step cannot be passed without anyway.
  if (autoSend && !asked && chosen?.kind === "email_code") {
    setAsked(true);
    void sendEmail();
  }

  if (usable.length === 0) {
    return (
      <>
        <Alert message={t("twofactor.unsupported.body", { providers: providers.map(providerName).join(", ") })} />
        {onBack && (
          <button type="button" className="btn" onClick={onBack}>
            {t("action.back")}
          </button>
        )}
      </>
    );
  }

  return (
    <form
      className="form"
      onSubmit={(e) => {
        e.preventDefault();
        if (!chosen) return;
        void run(async () => {
          await invoke("vault_login_two_factor", { provider: chosen.id, token });
          setToken("");
          onDone();
        });
      }}
    >
      {usable.length > 1 && (
        <div className="seg">
          {usable.map((p) => (
            <button
              key={p.id}
              type="button"
              className={chosen?.id === p.id ? "on" : ""}
              onClick={() => {
                setChosen(p);
                setSent(false);
              }}
            >
              {providerName(p)}
            </button>
          ))}
        </div>
      )}
      <div className="field">
        <label>{chosen ? providerPrompt(chosen) : ""}</label>
        <input
          value={token}
          onChange={(e) => setToken(e.target.value)}
          aria-label={t("twofactor.code")}
          placeholder={t("twofactor.code")}
          inputMode="numeric"
          autoFocus
          spellCheck={false}
        />
      </div>
      {(chosen?.kind === "email_code" || chosen?.kind === "new_device") && (
        <button type="button" className="link" disabled={busy} onClick={() => void sendEmail()}>
          {sent ? t("twofactor.resendEmail") : t("twofactor.sendEmail")}
        </button>
      )}
      {error && <Alert message={error} />}
      <button type="submit" className="btn primary" disabled={busy || !token}>
        {busy ? t("twofactor.checking") : t("twofactor.submit")}
      </button>
    </form>
  );
}

/// What to do with a "like Login" answer: either it is done, or a second
/// factor is needed.
/// Returns the providers when the step is needed, and `null` when it is
/// already done.
export function needsTwoFactor(reply: LoginReply): TwoFactorProvider[] | null {
  return reply.kind === "two_factor" ? reply.providers : null;
}
