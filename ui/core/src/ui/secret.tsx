// Secrets on the screen. A value is asked for at the moment it is shown and
// let go the moment it is not: on hide, when the window loses focus, when
// the field leaves the screen, and after thirty seconds. Until then the field
// shows dots. A copy goes through the backend, which clears the clipboard.
import { useCallback, useEffect, useRef, useState } from "react";
import { t } from "../i18n";
import type { SecretRef } from "../model/types";
import { IconButton, useCore } from "./marks";
import { isLockedError, RevealSession } from "./reveal-session";
import { Turning } from "./Loading";

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

/// The one-time code, counting down. It is asked for again when its period
/// runs out; the code is shown as long as the field is, like the concept's.
/// An item that asks for the master password again shows no code by itself:
/// a press asks for the password first (or, where the backend checks it
/// itself, asks the backend).
export function TotpCode({ itemId }: { itemId: string }) {
  const { reprompt } = useCore();
  const fail = useReportUnlessLocked();
  const [opened, setOpened] = useState<string | null>(null);
  if (!reprompt.isGuarded(itemId) || opened === itemId) return <TotpLive key={itemId} itemId={itemId} />;
  const open = () => {
    reprompt
      .confirm(itemId)
      .then((ok) => {
        if (ok) setOpened(itemId);
      })
      .catch(fail);
  };
  return (
    <span className="kw-totp">
      <IconButton icon="lock" tip={t("reprompt.show")} onClick={open} />
    </span>
  );
}

function TotpLive({ itemId }: { itemId: string }) {
  const { backend } = useCore();
  const fail = useReportUnlessLocked();
  const [code, setCode] = useState<{ code: string; period: number; at: number; remaining: number } | null>(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    let live = true;
    let next: ReturnType<typeof setTimeout> | null = null;
    const load = async () => {
      const c = await backend.totp(itemId);
      if (!live) return;
      setCode({ code: c.code, period: c.period, at: Date.now(), remaining: c.remaining });
      next = setTimeout(run, c.remaining * 1000 + 50);
    };
    const run = () => {
      load().catch((e: unknown) => {
        if (live) fail(e);
      });
    };
    run();
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      live = false;
      if (next) clearTimeout(next);
      clearInterval(tick);
      setCode(null);
    };
  }, [backend, itemId, fail]);
  // The ring's length is its circumference: 2π × 6.5.
  const C = 40.84;
  // The first code on its way: a bar of its breadth and a turning ring.
  if (!code)
    return (
      <span className="kw-totp kw-sk-late" role="status" aria-label={t("load.code")}>
        <span className="kw-sk kw-sk-code" aria-hidden="true" />
        <Turning className="kw-faint" />
      </span>
    );
  const left = Math.max(0, code.remaining - Math.floor((now - code.at) / 1000));
  const period = code.period;
  return (
    <span className="kw-totp">
      <span className="kw-code">{`${code.code.slice(0, 3)} ${code.code.slice(3)}`}</span>
      <svg className={`kw-ring${left <= 7 ? " kw-low" : ""}`} viewBox="0 0 16 16" aria-hidden="true">
        <circle className="kw-bg" cx="8" cy="8" r="6.5" />
        <circle className="kw-fg" cx="8" cy="8" r="6.5" strokeDasharray={C} style={{ strokeDashoffset: C * (1 - left / period) }} />
      </svg>
      <span className="kw-secs">{t("ui.seconds", { n: left })}</span>
    </span>
  );
}
