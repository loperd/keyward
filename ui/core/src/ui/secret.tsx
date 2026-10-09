// Secrets on the screen. A value is asked for at the moment it is shown and
// let go the moment it is not: on hide, when the window loses focus, when
// the field leaves the screen, and after thirty seconds. Until then the field
// shows dots. A copy goes through the backend, which clears the clipboard.
import { useCallback, useEffect, useRef, useState } from "react";
import type { SecretRef } from "../model/types";
import { useCore } from "./marks";
import { isLockedError, RevealSession } from "./reveal-session";

/// How long a revealed value stays on the screen.
export const REVEAL_MS = 30_000;

export type Reveal = { value: string | null; busy: boolean; show: () => Promise<void>; hide: () => void; toggle: () => void };

/// A failure said through the window's report, except a lock: the gate is
/// about to stand and says it by itself.
export function useReportUnlessLocked(): (e: unknown) => void {
  const { report } = useCore();
  return useCallback((e: unknown) => {
    if (!isLockedError(e)) report(e);
  }, [report]);
}

/// A secret shown for a moment. The value lives in state only while it is
/// shown; `drop` is called on every way it stops being shown, and an answer
/// that comes after the field stopped asking is dropped unseen (see
/// RevealSession). An item that asks for the master password again is asked
/// about before every reveal.
export function useReveal(ref: SecretRef | null): Reveal {
  const { backend, reprompt } = useCore();
  const fail = useReportUnlessLocked();
  const [value, setValue] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const session = useRef<RevealSession | null>(null);

  // A new reference is another secret: what was shown, or is on its way, goes.
  const key = ref ? JSON.stringify(ref) : "";
  useEffect(() => {
    const s = new RevealSession(setValue, () => document.hasFocus(), REVEAL_MS);
    session.current = s;
    setBusy(false);
    const onBlur = () => s.hide();
    const onHidden = () => {
      if (document.visibilityState === "hidden") s.hide();
    };
    window.addEventListener("blur", onBlur);
    document.addEventListener("visibilitychange", onHidden);
    return () => {
      window.removeEventListener("blur", onBlur);
      document.removeEventListener("visibilitychange", onHidden);
      s.dispose();
      if (session.current === s) session.current = null;
    };
  }, [key]);

  const hide = useCallback(() => session.current?.hide(), []);

  const show = useCallback(async () => {
    if (!ref) throw new Error("a secret without a reference cannot be revealed");
    const s = session.current;
    if (!s) return;
    setBusy(true);
    try {
      await s.show(
        () => backend.reveal(ref),
        () => reprompt.confirm(ref.itemId),
      );
    } finally {
      if (session.current === s) setBusy(false);
    }
  }, [backend, reprompt, ref]);

  const toggle = useCallback(() => {
    if (value !== null) hide();
    else show().catch(fail);
  }, [value, hide, show, fail]);

  return { value, busy, show, hide, toggle };
}

const DOTS: Record<string, string> = {
  password: "••••••••••••••",
  cardNumber: "•••• •••• ••••",
  cardCode: "•••",
  notes: "•••••••• ••••• ••••••••••",
  passport: "•• ••••••",
  phone: "+• ••• ••• ••",
};
/// Dots of a length that says what kind of value hides there, never its
/// length.
export const dotsFor = (key: string | null) => (key && DOTS[key]) ?? "••••••••";

