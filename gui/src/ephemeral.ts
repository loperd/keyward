/// Secrets the window has been shown, kept as briefly as possible.
///
/// A value revealed in the webview is a JavaScript string: it cannot be wiped,
/// only dropped and left to the collector. What can be done is to drop it
/// soon — each value on its own after a short while, and all of them the
/// moment the window loses the focus or is hidden: nobody is reading a
/// password in a window they have left.
import { useCallback, useEffect, useRef, useState } from "react";

/// How long a revealed value stays on the screen.
export const REVEAL_TTL_MS = 20_000;

export function useEphemeral(resetKey: unknown) {
  const [values, setValues] = useState<Record<string, string>>({});
  const timers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  const forget = useCallback((key: string) => {
    clearTimeout(timers.current[key]);
    delete timers.current[key];
    setValues((v) => {
      if (!(key in v)) return v;
      const next = { ...v };
      delete next[key];
      return next;
    });
  }, []);

  const forgetAll = useCallback(() => {
    for (const t of Object.values(timers.current)) clearTimeout(t);
    timers.current = {};
    setValues({});
  }, []);

  const keep = useCallback(
    (key: string, value: string) => {
      clearTimeout(timers.current[key]);
      timers.current[key] = setTimeout(() => forget(key), REVEAL_TTL_MS);
      setValues((v) => ({ ...v, [key]: value }));
    },
    [forget],
  );

  // Another item, another set: nothing carries over.
  useEffect(() => forgetAll, [resetKey, forgetAll]);

  useEffect(() => {
    const away = () => {
      if (document.visibilityState === "hidden" || !document.hasFocus()) forgetAll();
    };
    window.addEventListener("blur", forgetAll);
    document.addEventListener("visibilitychange", away);
    return () => {
      window.removeEventListener("blur", forgetAll);
      document.removeEventListener("visibilitychange", away);
    };
  }, [forgetAll]);

  return { values, keep, forget, forgetAll };
}
