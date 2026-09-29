import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { t } from "./i18n";
import { invokeSecret } from "./seal";

/// The standard TOTP step. Other periods exist, but the server does not report
/// them in the field, so the countdown is counted in thirty seconds — the code
/// itself always comes from the daemon and is never computed here.
const STEP = 30;

function remaining(): number {
  return STEP - (Math.floor(Date.now() / 1000) % STEP);
}

/// A live code and how long it has left. Asked for only when it is really
/// being shown: there is no point decrypting a secret in advance.
export function useTotpCode(entryId: string, enabled: boolean) {
  const [code, setCode] = useState<string | null>(null);
  const [left, setLeft] = useState(remaining());
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!enabled) return;
    invokeSecret("reveal_secret", { entryId, field: "totp" })
      .then((v) => {
        setCode(v);
        setError(null);
      })
      .catch((e) => setError(String(e)));
  }, [entryId, enabled]);

  useEffect(() => {
    if (!enabled) {
      setCode(null);
      return;
    }
    // The seconds are recomputed at once: otherwise, until the interval's
    // first tick, the screen holds a value computed when the row was mounted,
    // which may have been minutes ago.
    setLeft(remaining());
    load();
  }, [enabled, load]);

  useEffect(() => {
    if (!enabled) return;
    const id = setInterval(() => {
      const r = remaining();
      setLeft(r);
      // The window rolled over, so the code changed and is read again.
      if (r === STEP) load();
    }, 1000);
    return () => clearInterval(id);
  }, [enabled, load]);

  return { code, left, error, reload: load };
}

/// Split in half, it reads noticeably faster than an unbroken run of
/// digits.
export function prettyCode(code: string): string {
  const half = Math.ceil(code.length / 2);
  return code.length >= 6 ? `${code.slice(0, half)} ${code.slice(half)}` : code;
}

/// The countdown ring. The seconds stand beside it rather than inside: at that
/// size a digit over an arc cannot be read.
export function Countdown({ left }: { left: number }) {
  return (
    <span className="count">
      <span
        className={`ring ${left <= 5 ? "soon" : ""}`}
        style={{ ["--p" as string]: `${(left / STEP) * 360}deg` }}
        aria-hidden="true"
      />
      <span className="secs">{left}</span>
    </span>
  );
}

/// A live one-time code on an item's card.
export function Totp({ entryId, onError }: { entryId: string; onError?: (e: string) => void }) {
  const { code, left, error, reload } = useTotpCode(entryId, true);
  const [restoring, setRestoring] = useState(false);
  const [restoreError, setRestoreError] = useState<string | null>(null);
  // A secret a code was saved over can be put back from the journal of edits:
  // the daemon finds the last real one and changes nothing else.
  const restore = async () => {
    setRestoring(true);
    setRestoreError(null);
    try {
      await invoke("restore_totp", { entryId });
      reload();
    } catch (e) {
      setRestoreError(String(e));
    } finally {
      setRestoring(false);
    }
  };

  useEffect(() => {
    if (error) onError?.(error);
  }, [error, onError]);

  // The error lives in the field's own row: the item's card does not disappear
  // over it, and the other fields read and copy as usual.
  if (error)
    return (
      <span className="v totp-err" role="alert">
        {restoreError ?? error}
        {!restoreError && (
          <button type="button" className="btn small" disabled={restoring} onClick={() => void restore()}>
            {t("totp.restore")}
          </button>
        )}
      </span>
    );

  if (!code) return <span className="v mono">······</span>;

  return (
    <span className="totp">
      {/* The key is the value: when the code changes the node is recreated and
          plays a short transition. The tick of the seconds is not animated — a
          digit jerking every second only gets in the way of reading. */}
      <span className="v mono code swap" key={code}>
        {prettyCode(code)}
      </span>
      <Countdown left={left} />
    </span>
  );
}
