// The re-prompt's sheet: the master password once more, for one item, before
// a copy, a reveal or a one-time code. The field is uncontrolled
// (SecretInput): the password goes from it to the backend with the press and
// is not kept anywhere. Escape or "Cancel" gives up, and nothing is fetched.
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import "./reprompt.css";
import { t, text } from "../i18n";
import { Icon } from "./Icons";
import { Mark } from "./marks";
import type { Reprompt } from "./reprompt";
import { SecretInput, type SecretInputHandle } from "./secret-input";
import { Level } from "../model/types";

export function RepromptPrompt({ reprompt }: { reprompt: Reprompt }) {
  const ask = useSyncExternalStore(reprompt.subscribe, reprompt.get);
  const field = useRef<SecretInputHandle>(null);
  const [filled, setFilled] = useState(false);
  useEffect(() => {
    if (!ask) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      e.stopPropagation();
      reprompt.cancel();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [ask, reprompt]);
  // A refusal leaves the field empty and ready for another try.
  useEffect(() => {
    if (ask?.error) field.current?.focus();
  }, [ask?.error]);
  if (!ask) return null;
  const submit = () => {
    if (ask.busy || !filled || !field.current) return;
    void reprompt.submit(field.current.take());
  };
  return (
    <div className="kw-reprompt-veil" onClick={(e) => e.target === e.currentTarget && !ask.busy && reprompt.cancel()}>
      <form
        key={ask.itemId}
        className="kw-reprompt"
        role="dialog"
        aria-modal="true"
        aria-label={t("reprompt.title")}
        aria-busy={ask.busy}
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <div className="kw-reprompt-h">
          <Icon name="lock" />
          <span>{t("reprompt.title")}</span>
        </div>
        <p>{t("reprompt.lede")}</p>
        <span className="kw-reprompt-in">
          <SecretInput ref={field} onFilled={setFilled} autoComplete="current-password" autoFocus disabled={ask.busy} aria-label={t("reprompt.password")} placeholder={t("reprompt.password")} />
        </span>
        {ask.error && (
          <div role="alert">
            <Mark level={Level.Critical} words={text(ask.error)} />
          </div>
        )}
        <div className="kw-reprompt-go">
          <button type="button" className="kw-btn" onClick={() => reprompt.cancel()} disabled={ask.busy}>
            {t("reprompt.cancel")}
          </button>
          <button type="submit" className="kw-btn kw-solid" disabled={ask.busy || !filled}>
            {t(ask.busy ? "reprompt.checking" : "reprompt.confirm")}
          </button>
        </div>
      </form>
    </div>
  );
}
