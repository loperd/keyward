// The browser extensions that may ask for passkeys. A new one asks, is
// refused with its five words, and shows up to be paired: the person compares
// the words with the extension's window and pairs, with the finger. The list
// on the Browsers page and the prompt over the window both read the backend
// on a timer, so a browser that asks while the window is open shows up
// without a reload.
import { faultWords } from "./fault";
import { useCallback, useEffect, useState } from "react";
import "./reprompt.css";
import "./extensions.css";
import { currentLang, t } from "../i18n";
import type { BrowserExtension, BrowserExtensions } from "../settings/types";
import { Icon } from "./Icons";
import { IconButton, Mark, Tile, useCore } from "./marks";
import { LeadTile } from "../doc/spec";
import { pageId, SettingsPage } from "../settings/pages";
import { Phase } from "./feedback";
import { Level } from "../model/types";
import { ToastKind } from "./toasts";

/// The extension's page in the Chrome Web Store.
export const EXTENSION_STORE_URL = "https://chromewebstore.google.com/detail/keyward/codlckblccbcnadacdnoieimkmdieajg";

/// How often the list and the prompt look again, in milliseconds.
const LIST_EVERY = 5000;
const PROMPT_EVERY = 3000;

function Words({ words }: { words: string[] }) {
  return (
    <span className="ext-words">
      {words.map((w, i) => (
        <code key={i}>{w}</code>
      ))}
    </span>
  );
}

const since = (at: number) => t("ext.since", { date: new Date(at * 1000).toLocaleDateString(currentLang(), { day: "numeric", month: "long", year: "numeric" }) });
const used = (at: number) => t("ext.used", { when: new Date(at * 1000).toLocaleString(currentLang(), { day: "numeric", month: "long", hour: "2-digit", minute: "2-digit" }) });

/// What is known of where an extension is: the Mac, when it was paired, its
/// last request.
const about = (r: BrowserExtension, paired: boolean) =>
  [r.device, paired ? since(r.at) : null, r.used !== null ? used(r.used) : null].filter((x): x is string => !!x).join(" · ");

/// The browsers paired, by name, or how many when one has none.
const pairedNames = (rows: BrowserExtension[]) => {
  const names = [...new Set(rows.map((r) => r.browser))];
  return names.every((n): n is string => n !== null) ? names.join(", ") : t("ext.rowPaired", { n: rows.length });
};

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
      (e: unknown) => setFailed(faultWords(e)),
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
      <div className="set set-wait" role="status" aria-label={t("set.loading")}>
        <span className="set-t">
          <b>{t("set.loading")}</b>
        </span>
      </div>
    );
  const install = (solid: boolean) =>
    b.openUrl && (
      <button type="button" className={`btn${solid ? " solid" : " quiet"}`} onClick={() => b.openUrl!(EXTENSION_STORE_URL).catch(core.report)}>
        <Icon name="ext" />
        {t("ext.install")}
      </button>
    );
  if (!list.paired.length && !list.pending.length)
    return (
      <div className="set">
        <span className="set-t">
          <b>{t("ext.none")}</b>
          <span className="set-h">{t("ext.noneHint")}</span>
        </span>
        <span className="set-acts">{install(true)}</span>
      </div>
    );
  return (
    <>
      {list.pending.map((r) => (
        <div key={r.key} className="set ext">
          <span className="set-t">
            <b>{r.browser ? t("ext.askingFrom", { browser: r.browser }) : t("ext.asking")}</b>
            {r.device && <span className="set-h">{about(r, false)}</span>}
            <Words words={r.words} />
          </span>
          <button type="button" className="btn solid" disabled={busy !== null} aria-busy={busy === r.key || undefined} onClick={() => b.pairExtension && act(r.key, () => b.pairExtension!(r.key), t("ext.pairedToast"))}>
            <Icon name="finger" />
            {t(busy === r.key ? "pair.touch" : "ext.pair")}
          </button>
        </div>
      ))}
      {list.paired.map((r) => (
        <div key={r.key} className="set ext">
          <span className="set-t">
            <b title={r.browser ? undefined : t("ext.unknownBrowser")}>{r.browser ?? t("ext.paired")}</b>
            <span className="set-h">{about(r, true)}</span>
            <Words words={r.words} />
          </span>
          <IconButton icon="trash" tip={t("ext.unpair")} phase={busy === r.key ? Phase.Busy : Phase.Idle} onClick={() => b.unpairExtension && busy === null && act(r.key, () => b.unpairExtension!(r.key), t("ext.unpaired"))} />
        </div>
      ))}
      <div className="set">
        <span className="set-t">
          <b>{t("ext.another")}</b>
          <span className="set-h">{t("ext.anotherHint")}</span>
        </span>
        <span className="set-acts">{install(false)}</span>
      </div>
    </>
  );
}

/// The browsers among the vault's connections on its home: how many are
/// paired, or that the extension is still to be installed; it leads to the
/// Browsers page, where it is installed and paired.
export function BrowsersRow() {
  const { backend, store } = useCore();
  const [list, setList] = useState<BrowserExtensions | null>(null);
  useEffect(() => {
    if (!backend.extensions) return;
    let live = true;
    backend.extensions().then((l) => live && setList(l), (e: unknown) => console.error(e));
    return () => {
      live = false;
    };
  }, [backend]);
  const asking = list?.pending.length ?? 0;
  const paired = list?.paired.length ?? 0;
  return (
    <div className="ref" onClick={() => store.go(pageId(SettingsPage.Browsers))}>
      <Tile lead={{ tile: LeadTile.Plain, icon: "login" }} />
      <span className="rt">{t("set.page.browsers")}</span>
      <span className="rc">{t("ext.rowSub")}</span>
      <span className="rs">
        {list &&
          (asking ? (
            <Mark level={Level.Action} words={t("ext.rowAsking", { n: asking })} />
          ) : paired ? (
            <Mark level={Level.Healthy} words={pairedNames(list.paired)} />
          ) : (
            <Mark level={Level.Warning} words={t("ext.rowNone")} />
          ))}
      </span>
    </div>
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
      .catch((e: unknown) => setError(faultWords(e)))
      .finally(() => setBusy(false));
  };
  return (
    <div className="reprompt-veil" onClick={(e) => e.target === e.currentTarget && !busy && later()}>
      <div className="reprompt pair" role="dialog" aria-modal="true" aria-label={t("pair.title")} aria-busy={busy}>
        <div className="reprompt-h">
          <Icon name="login" />
          <span>{asking.browser ? t("ext.askingFrom", { browser: asking.browser }) : t("pair.title")}</span>
        </div>
        <p>{t("pair.body")}</p>
        <Words words={asking.words} />
        <p className={`pair-timer${expired ? " expired" : ""}`}>
          <Icon name="clock" />
          {expired ? t("pair.expired") : t("pair.left", { left: `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` })}
        </p>
        {error && (
          <div role="alert">
            <Mark level={Level.Critical} words={error} />
          </div>
        )}
        <div className="reprompt-go">
          <button type="button" className="btn" onClick={later} disabled={busy}>
            {t("pair.later")}
          </button>
          <button type="button" className="btn solid" onClick={pair} disabled={busy || expired} autoFocus>
            <Icon name="finger" />
            {t(busy ? "pair.touch" : "pair.confirm")}
          </button>
        </div>
      </div>
    </div>
  );
}
