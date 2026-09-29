import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Alert, Icon } from "./ui";
import { t } from "./i18n";
import type { Key } from "./i18n";
import type { LoginReply, Status, TwoFactorProvider, VaultState } from "./types";
import { PasswordInput } from "./PasswordInput";
import { TwoFactorForm } from "./TwoFactor";

const US = "https://vault.bitwarden.com";
const EU = "https://vault.bitwarden.eu";

function useAction(onChanged: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run, clear: () => setError(null) };
}

function Crest({ title, sub }: { title: string; sub?: string }) {
  return (
    <div className="crest">
      <span className="badge">
        <Icon name="shield" size={22} />
      </span>
      <h2>{title}</h2>
      {sub && <p>{sub}</p>}
    </div>
  );
}

/// The gate: exactly one screen is shown, the one the state calls for.
export function Gate({
  status,
  onChanged,
  forceSetup,
  onSetupDone,
}: {
  status: Status;
  onChanged: () => void;
  forceSetup: boolean;
  onSetupDone: () => void;
}) {
  const v = status.vault;
  if (forceSetup || v.state === "needs_setup") {
    return <Setup onChanged={onChanged} onDone={onSetupDone} closable={v.state !== "needs_setup"} />;
  }
  if (v.state === "unlocked" || v.state === "disabled") return null;
  if (v.state === "logged_out") return <Login vault={v} onChanged={onChanged} onEdit={onSetupDone} />;
  if (v.state === "locked") return <Unlock vault={v} biometric={status.biometric} pin={status.pin} onChanged={onChanged} />;
  return null;
}

function Setup({ onChanged, onDone, closable }: { onChanged: () => void; onDone: () => void; closable: boolean }) {
  const [region, setRegion] = useState<"us" | "eu" | "self">("us");
  const [url, setUrl] = useState("");
  const [identityUrl, setIdentityUrl] = useState("");
  const [email, setEmail] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const { busy, error, run } = useAction(onChanged);

  useEffect(() => {
    invoke<{ base_url: string; email: string; identity_url: string | null }>("vault_config")
      .then((c) => {
        setEmail(c.email ?? "");
        setIdentityUrl(c.identity_url ?? "");
        if (c.identity_url) setAdvanced(true);
        if (!c.base_url || c.base_url === US) setRegion("us");
        else if (c.base_url === EU) setRegion("eu");
        else {
          setRegion("self");
          setUrl(c.base_url);
        }
      })
      .catch(() => {});
  }, []);

  const baseUrl = region === "us" ? US : region === "eu" ? EU : url;

  return (
    <div className="gate">
      <div className="gate-card">
        <Crest title={t("setup.title")} />
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              await invoke("vault_setup", {
                baseUrl,
                email,
                identityUrl: region === "self" && identityUrl ? identityUrl : null,
              });
              onDone();
            });
          }}
        >
          <div className="seg">
            {(["us", "eu", "self"] as const).map((r) => (
              <button key={r} type="button" className={region === r ? "on" : ""} onClick={() => setRegion(r)}>
                {t(`setup.region.${r}` as Key)}
              </button>
            ))}
          </div>

          {region === "self" && (
            <>
              <input value={url} onChange={(e) => setUrl(e.target.value)} aria-label={t("setup.url")} placeholder={t("setup.url")} spellCheck={false} autoCapitalize="off" />
              {advanced ? (
                <input
                  value={identityUrl}
                  onChange={(e) => setIdentityUrl(e.target.value)}
                  aria-label={t("setup.identity")} placeholder={t("setup.identity")}
                  spellCheck={false}
                  autoCapitalize="off"
                />
              ) : (
                <button type="button" className="link" onClick={() => setAdvanced(true)}>
                  {t("setup.identityToggle")}
                </button>
              )}
            </>
          )}

          <input value={email} onChange={(e) => setEmail(e.target.value)} aria-label={t("setup.login")} placeholder={t("setup.login")} spellCheck={false} autoCapitalize="off" />
          {error && <Alert message={error} />}
          <button type="submit" className="btn primary" disabled={busy || !email || (region === "self" && !url)}>
            {busy ? t("action.saving") : t("action.save")}
          </button>
          {closable && (
            <button type="button" className="link" onClick={onDone}>
              {t("action.cancel")}
            </button>
          )}
        </form>
      </div>
    </div>
  );
}

function Login({
  vault,
  onChanged,
  onEdit,
}: {
  vault: Extract<VaultState, { state: "logged_out" }>;
  onChanged: () => void;
  onEdit: () => void;
}) {
  const [password, setPassword] = useState("");
  const [providers, setProviders] = useState<TwoFactorProvider[] | null>(null);
  const { busy, error, run } = useAction(onChanged);

  if (providers) {
    const usable = providers.filter((p) => p.kind !== "unsupported");
    return (
      <div className="gate">
        <div className="gate-card">
          <Crest title={usable.length === 0 ? t("twofactor.unsupported.title") : t("twofactor.title")} sub={vault.email} />
          <TwoFactorForm
            providers={providers}
            onDone={() => {
              setProviders(null);
              onChanged();
            }}
            onBack={() => setProviders(null)}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="gate">
      <div className="gate-card">
        <Crest title={t("login.title")} sub={`${vault.email} · ${vault.server}`} />
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              const reply = await invoke<LoginReply>("vault_login", { password });
              setPassword("");
              if (reply.kind === "two_factor") setProviders(reply.providers);
            });
          }}
        >
          <PasswordInput value={password} onChange={setPassword} placeholder={t("login.password")} autoFocus />
          {error && <Alert message={error} />}
          <button type="submit" className="btn primary" disabled={busy || !password}>
            {busy ? t("login.progress") : t("login.submit")}
          </button>
          <button type="button" className="link" onClick={onEdit}>
            {t("login.changeServer")}
          </button>
        </form>
      </div>
    </div>
  );
}

function Unlock({
  vault,
  biometric,
  pin,
  onChanged,
}: {
  vault: Extract<VaultState, { state: "locked" }>;
  biometric: boolean;
  /// Whether a PIN is set: then it is shown first and the password comes by a
  /// link.
  pin: boolean;
  onChanged: () => void;
}) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  // While Touch ID is set up there is no need to ask for a password: the
  // finger first, and the input field only if that did not work.
  const [asking, setAsking] = useState(biometric);
  // A PIN is shorter than a password and is the default path when one is set.
  // It falls back to the password after five misses (`err.pinReset`) or by a
  // link.
  const [byPin, setByPin] = useState(pin);
  const [pinReset, setPinReset] = useState(false);
  const { busy, error, run, clear } = useAction(onChanged);
  const tried = useRef(false);

  const touchId = () => {
    setAsking(true);
    void run(() => invoke("biometric_unlock")).finally(() => setAsking(false));
  };

  useEffect(() => {
    // Exactly once per showing of the screen: a system prompt that jumps out
    // on every redrawn frame is a nightmare.
    if (!biometric || tried.current) return;
    tried.current = true;
    touchId();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [biometric]);

  // The daemon erased the PIN after five wrong tries: the error arrives as a
  // code, and the screen switches to the password itself, with the reason.
  useEffect(() => {
    if (error && error.includes("err.pinReset")) {
      setByPin(false);
      setPinReset(true);
      setCode("");
      clear();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [error]);

  if (asking) {
    return (
      <div className="gate">
        <div className="gate-card">
          <Crest title={t("unlock.title")} sub={vault.email} />
          <p className="hint" style={{ textAlign: "center" }}>
            {t("unlock.touchIdWaiting")}
          </p>
        </div>
      </div>
    );
  }

  const usingPin = byPin && pin;

  return (
    <div className="gate">
      <div className="gate-card">
        <Crest title={t("unlock.title")} sub={`${vault.email} · ${vault.server}`} />
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              if (usingPin) {
                await invoke("pin_unlock", { pin: code });
                setCode("");
              } else {
                await invoke("vault_unlock", { password });
                setPassword("");
              }
            });
          }}
        >
          {usingPin ? (
            <PasswordInput value={code} onChange={setCode} placeholder={t("unlock.pin")} autoFocus inputMode="numeric" />
          ) : (
            <PasswordInput value={password} onChange={setPassword} placeholder={t("login.password")} autoFocus />
          )}
          {pinReset && <Alert tone="warn" message={t("err.pinReset")} onClose={() => setPinReset(false)} />}
          {error && <Alert message={error} />}
          <button type="submit" className="btn primary" disabled={busy || (usingPin ? !code : !password)}>
            {busy ? t("unlock.progress") : t("unlock.submit")}
          </button>
          {biometric ? (
            <button type="button" className="btn" disabled={busy} onClick={touchId}>
              {tried.current ? t("unlock.touchIdRetry") : t("unlock.touchId")}
            </button>
          ) : (
            // Without this line, an absent Touch ID looks like a fault rather
            // than a setting nobody switched on.
            <span className="hint" style={{ textAlign: "center" }}>
              {t("unlock.noTouchId")}
            </span>
          )}
          {pin && (
            <button
              type="button"
              className="link"
              onClick={() => {
                setByPin((v) => !v);
                clear();
              }}
            >
              {usingPin ? t("unlock.usePassword") : t("unlock.usePin")}
            </button>
          )}
        </form>
      </div>
    </div>
  );
}
