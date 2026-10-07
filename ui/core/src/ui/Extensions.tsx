// The browser extensions that may ask for passkeys. A new one asks, is
// refused with its five words, and shows up to be paired: the person compares
// the words with the extension's window and pairs, with the finger. The list
// on the Browsers page and the prompt over the window both read the backend
// on a timer, so a browser that asks while the window is open shows up
// without a reload.
import { useCallback, useEffect, useState } from "react";
import "./reprompt.css";
import "./extensions.css";
import { currentLang, t } from "../i18n";
import type { BrowserExtension, BrowserExtensions } from "../settings/types";
import { Icon } from "./Icons";
import { IconButton, Mark, useCore } from "./marks";
import { Phase } from "./feedback";
import { Level } from "../model/types";
import { ToastKind } from "./toasts";

/// How often the list and the prompt look again, in milliseconds.
const LIST_EVERY = 5000;
const PROMPT_EVERY = 3000;

function Words({ words }: { words: string[] }) {
  return (
    <span className="kw-ext-words">
      {words.map((w, i) => (
        <code key={i}>{w}</code>
      ))}
    </span>
  );
}

const since = (at: number) => t("ext.since", { date: new Date(at * 1000).toLocaleDateString(currentLang(), { day: "numeric", month: "long", year: "numeric" }) });

/// The Browsers page's list: the ones asking first, then the paired.
export function ExtensionsList() {
  const core = useCore();
  const b = core.backend;
  const [list, setList] = useState<BrowserExtensions | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const load = useCallback(() => {
    if (!b.extensions) return;
    b.extensions().then(
      (l) => {
        setList(l);
        setFailed(null);
      },
      (e: unknown) => setFailed(e instanceof Error ? e.message : String(e)),
    );
  }, [b]);
  useEffect(() => {
    load();
    const timer = setInterval(load, LIST_EVERY);
    return () => clearInterval(timer);
  }, [load]);
  const act = (key: string, run: () => Promise<BrowserExtensions>, done: string) => {
    setBusy(key);
    run()
      .then((l) => {
        setList(l);
        core.toast(ToastKind.Ok, done);
      }, core.report)
      .finally(() => setBusy(null));
  };
  if (failed && !list) return <Mark level={Level.Critical} words={t("ext.failed", { reason: failed })} />;
  if (!list)
    return (
      <div className="kw-set kw-set-wait" role="status" aria-label={t("set.loading")}>
        <span className="kw-set-t">
          <b>{t("set.loading")}</b>
        </span>
      </div>
    );
  if (!list.paired.length && !list.pending.length)
    return (
      <div className="kw-set">
        <span className="kw-set-t">
          <b>{t("ext.none")}</b>
          <span className="kw-set-h">{t("ext.noneHint")}</span>
        </span>
        <Icon name="login" />
      </div>
    );
  return (
    <>
      {list.pending.map((r) => (
        <div key={r.key} className="kw-set kw-ext">
          <span className="kw-set-t">
            <b>{t("ext.asking")}</b>
            <Words words={r.words} />
          </span>
          <button type="button" className="kw-btn kw-solid" disabled={busy !== null} aria-busy={busy === r.key || undefined} onClick={() => b.pairExtension && act(r.key, () => b.pairExtension!(r.key), t("ext.pairedToast"))}>
            <Icon name="finger" />
            {t(busy === r.key ? "pair.touch" : "ext.pair")}
          </button>
        </div>
      ))}
      {list.paired.map((r) => (
        <div key={r.key} className="kw-set kw-ext">
          <span className="kw-set-t">
            <b>
              {t("ext.paired")} <span className="kw-set-h">· {since(r.at)}</span>
            </b>
            <Words words={r.words} />
          </span>
          <IconButton icon="trash" tip={t("ext.unpair")} phase={busy === r.key ? Phase.Busy : Phase.Idle} onClick={() => b.unpairExtension && busy === null && act(r.key, () => b.unpairExtension!(r.key), t("ext.unpaired"))} />
        </div>
      ))}
    </>
  );
}

/// A browser asking to be paired comes to the person while the vault is open:
/// its words to compare, the time they still count, one action. "Not now"
/// sets that one aside until the window is opened again; it still waits on
/// the Browsers page.
export function PairPrompt() {
  const core = useCore();
  const b = core.backend;
  const [asking, setAsking] = useState<BrowserExtension | null>(null);
  const [aside, setAside] = useState<ReadonlySet<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now() / 1000);
  useEffect(() => {
    if (!b.extensions) return;
    let alive = true;
    const look = () =>
      b.extensions!().then(
        (l) => {
          if (!alive) return;
          setAsking((cur) => (cur && l.pending.some((r) => r.key === cur.key) ? cur : (l.pending.find((r) => !aside.has(r.key)) ?? null)));
        },
        // The prompt is no screen of its own: a failed look is said once
        // in the console and tried again on the next turn.
        (e: unknown) => console.error(e),
      );
    void look();
    const timer = setInterval(look, PROMPT_EVERY);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [b, aside]);
  useEffect(() => {
    if (!asking) return;
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(timer);
  }, [asking]);
  useEffect(() => {
    if (!asking) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) later();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  });
  if (!asking) return null;
  const left = Math.max(0, Math.round(asking.expires - now));
  const expired = left === 0;
  function later() {
    if (!asking) return;
    setAside((s) => new Set([...s, asking.key]));
    setAsking(null);
    setError(null);
  }
  const pair = () => {
    if (!b.pairExtension) return;
    setBusy(true);
    setError(null);
    b.pairExtension(asking.key)
      .then(() => {
        setAsking(null);
        core.toast(ToastKind.Ok, t("ext.pairedToast"));
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setBusy(false));
  };
  return (
    <div className="kw-reprompt-veil" onClick={(e) => e.target === e.currentTarget && !busy && later()}>
      <div className="kw-reprompt kw-pair" role="dialog" aria-modal="true" aria-label={t("pair.title")} aria-busy={busy}>
        <div className="kw-reprompt-h">
          <Icon name="login" />
          <span>{t("pair.title")}</span>
        </div>
        <p>{t("pair.body")}</p>
        <Words words={asking.words} />
        <p className={`kw-pair-timer${expired ? " kw-expired" : ""}`}>
          <Icon name="clock" />
          {expired ? t("pair.expired") : t("pair.left", { left: `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` })}
        </p>
        {error && (
          <div role="alert">
            <Mark level={Level.Critical} words={error} />
          </div>
        )}
        <div className="kw-reprompt-go">
          <button type="button" className="kw-btn" onClick={later} disabled={busy}>
            {t("pair.later")}
          </button>
          <button type="button" className="kw-btn kw-solid" onClick={pair} disabled={busy || expired} autoFocus>
            <Icon name="finger" />
            {t(busy ? "pair.touch" : "pair.confirm")}
          </button>
        </div>
      </div>
    </div>
  );
}
