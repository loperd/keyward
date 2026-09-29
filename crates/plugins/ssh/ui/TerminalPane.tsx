import "@xterm/xterm/css/xterm.css";
import { useEffect, useRef, useState } from "react";
import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import { Alert, Icon, copyText } from "@keyward/ui";
import { t, tError } from "@keyward/i18n";
import { Controller } from "./controller";
import { closeTab, patchTab, reconnectTab, registerCloser, stepFont, useFontSize, type Tab } from "./terminalState";

/// A colour token of the window's theme, as it is now.
function token(name: string, fallback: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

/// Whether a `#rrggbb` colour is light.
function light(hex: string): boolean {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex);
  if (!m) return false;
  const n = parseInt(m[1], 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b > 150;
}

function translucent(hex: string, alpha: string): string {
  return /^#[0-9a-f]{6}$/i.test(hex) ? `${hex}${alpha}` : hex;
}

/// The terminal's colours out of the window's palette: the same accents, the
/// same grounds, in the light theme and the dark one alike.
function theme(): ITheme {
  const background = token("--block", "#20202c");
  const text = token("--text", "#f0eff8");
  const dim = token("--dim", "#a6a4b6");
  const faint = token("--faint", "#777587");
  const raise = token("--raise", "#292837");
  const sky = token("--sky", "#b4a8ff");
  const isLight = light(background);
  const red = token("--rose", "#ff6f7d");
  const green = token("--mint", "#42d6a4");
  const yellow = token("--amber", "#f2c14e");
  const blue = token("--blue-hi", "#8d7cff");
  const orange = token("--orange", "#ff9560");
  const cyan = isLight ? "#0f7f8f" : "#4fc8d8";
  return {
    background,
    foreground: text,
    cursor: sky,
    cursorAccent: background,
    selectionBackground: translucent(sky, "55"),
    black: isLight ? text : raise,
    red,
    green,
    yellow,
    blue,
    magenta: sky,
    cyan,
    white: isLight ? faint : dim,
    brightBlack: faint,
    brightRed: red,
    brightGreen: green,
    brightYellow: orange,
    brightBlue: blue,
    brightMagenta: sky,
    brightCyan: cyan,
    brightWhite: isLight ? dim : text,
  };
}

const IS_MAC = navigator.platform.toLowerCase().includes("mac");

/// The window's own command key: Cmd on a Mac. Elsewhere Ctrl+Shift, so that
/// Ctrl alone keeps reaching the shell — Ctrl+C has to stay an interrupt.
function command(e: KeyboardEvent): boolean {
  return IS_MAC ? e.metaKey && !e.ctrlKey : e.ctrlKey && e.shiftKey;
}

/// One tab's terminal. It stays mounted while other tabs are shown, so its
/// screen and scrollback survive switching; `visible` says whether it is the
/// one on view.
export function TerminalPane({ tab, visible }: { tab: Tab; visible: boolean }) {
  const host = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const search = useRef<SearchAddon | null>(null);
  const controller = useRef<Controller | null>(null);
  const [broken, setBroken] = useState<string | null>(null);
  const [finding, setFinding] = useState(false);
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const fontSize = useFontSize();

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    setBroken(null);
    const t0 = new Terminal({
      fontFamily: token("--mono", "IBM Plex Mono, ui-monospace, Menlo, monospace"),
      fontSize,
      lineHeight: 1.15,
      cursorBlink: true,
      scrollback: 10000,
      allowProposedApi: true,
      macOptionIsMeta: true,
      theme: theme(),
    });
    const f = new FitAddon();
    const s = new SearchAddon();
    t0.loadAddon(f);
    t0.loadAddon(s);
    t0.loadAddon(new Unicode11Addon());
    t0.unicode.activeVersion = "11";
    t0.open(el);
    f.fit();
    term.current = t0;
    fit.current = f;
    search.current = s;

    t0.attachCustomKeyEventHandler((e) => {
      if (e.type !== "keydown" || !command(e)) return true;
      const key = e.key.toLowerCase();
      // The window's own shortcuts stop here: Cmd+K is "clear" in a terminal,
      // not the window's search.
      if (key === "c" && t0.hasSelection()) {
        // Through the daemon: hidden from clipboard managers and cleared on
        // time — a terminal's output may well be a secret.
        void copyText(t0.getSelection());
        e.preventDefault();
        return false;
      }
      if (key === "v" && !IS_MAC) {
        void navigator.clipboard.readText().then((text) => t0.paste(text));
        e.preventDefault();
        return false;
      }
      if (key === "k") {
        t0.clear();
      } else if (key === "f") {
        setFinding(true);
      } else if (key === "=" || key === "+") {
        stepFont(1);
      } else if (key === "-") {
        stepFont(-1);
      } else if (key === "0") {
        stepFont(0);
      } else {
        return true;
      }
      e.preventDefault();
      e.stopPropagation();
      return false;
    });

    const ctl = new Controller(t0, tab.session, tab.destination, {
      onInfo: (info) => patchTab(tab.key, { info, session: info.id }),
      onState: (state) => patchTab(tab.key, { state }),
      onBroken: (error) => setBroken(error),
    });
    controller.current = ctl;
    void ctl.start();
    const unregister = registerCloser(tab.key, () => ctl.close());

    // The window's palette can change under a running terminal.
    const retheme = () => {
      t0.options.theme = theme();
    };
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    media.addEventListener("change", retheme);
    const watcher = new MutationObserver(retheme);
    watcher.observe(document.documentElement, { attributes: true, attributeFilter: ["style", "class", "data-theme"] });

    const resize = new ResizeObserver(() => {
      if (el.offsetWidth > 0 && el.offsetHeight > 0) f.fit();
    });
    resize.observe(el);

    return () => {
      unregister();
      resize.disconnect();
      watcher.disconnect();
      media.removeEventListener("change", retheme);
      ctl.stop();
      t0.dispose();
      term.current = null;
      controller.current = null;
    };
    // The terminal is made once per shell: a new epoch is a new shell.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab.key, tab.epoch]);

  useEffect(() => {
    const t0 = term.current;
    if (!t0) return;
    t0.options.fontSize = fontSize;
    fit.current?.fit();
  }, [fontSize]);

  useEffect(() => {
    if (!visible) return;
    const frame = requestAnimationFrame(() => {
      fit.current?.fit();
      term.current?.focus();
    });
    return () => cancelAnimationFrame(frame);
  }, [visible]);

  // A shell that has just opened takes the keyboard: the button that let it
  // open — "trust", say — must not keep the focus.
  useEffect(() => {
    if (visible && tab.state.kind === "open") term.current?.focus();
  }, [visible, tab.state.kind]);

  const state = tab.state;
  const where = tab.info ? `${tab.info.user}@${tab.info.host}` : (tab.destination?.host ?? "");

  const answer = async (yes: boolean) => {
    setBusy(true);
    try {
      await controller.current?.trust(yes);
    } catch (e) {
      setBroken(String(e));
    } finally {
      setBusy(false);
    }
  };

  const find = (backwards = false) => {
    if (!query) return;
    const opts = { caseSensitive: false, decorations: { matchOverviewRuler: "#888", activeMatchColorOverviewRuler: "#fff" } };
    if (backwards) search.current?.findPrevious(query, opts);
    else search.current?.findNext(query, opts);
  };

  return (
    <div className={`term-pane ${visible ? "" : "hidden"}`}>
      <div className="term-host" ref={host} onMouseDown={() => term.current?.focus()} />

      {finding && (
        <div className="term-find">
          <Icon name="search" size={14} />
          <input
            autoFocus
            value={query}
            spellCheck={false}
            placeholder={t("term.find")}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") find(e.shiftKey);
              if (e.key === "Escape") {
                e.stopPropagation();
                setFinding(false);
                search.current?.clearDecorations();
                term.current?.focus();
              }
            }}
          />
          <button type="button" className="btn icon-only" title={t("term.findPrev")} aria-label={t("term.findPrev")} onClick={() => find(true)}>
            <Icon name="chevron" size={13} />
          </button>
          <button
            type="button"
            className="btn icon-only"
            title={t("detail.close")}
            aria-label={t("detail.close")}
            onClick={() => {
              setFinding(false);
              search.current?.clearDecorations();
              term.current?.focus();
            }}
          >
            <Icon name="close" size={13} />
          </button>
        </div>
      )}

      {state.kind === "connecting" && !broken && (
        <div className="term-overlay">
          <div className="term-card">
            <span className="term-spinner" aria-hidden="true" />
            <b>{t("term.connecting", { where })}</b>
          </div>
        </div>
      )}

      {state.kind === "authenticating" && !broken && (
        <div className="term-overlay">
          <div className="term-card">
            <Icon name="key" size={20} />
            <b>{t("term.authenticating")}</b>
            <p className="hint">{t("term.authenticatingHint", { key: tab.info?.entry_name ?? "", where })}</p>
          </div>
        </div>
      )}

      {state.kind === "verify" && !broken && (
        <div className="term-overlay">
          <div className="term-card wide" role="dialog" aria-label={t("term.verify.title", { host: state.prompt.host })}>
            <Icon name="shield" size={20} />
            <b>{t("term.verify.title", { host: state.prompt.host })}</b>
            <p className="hint">{t("term.verify.body")}</p>
            <div className="term-fingerprint">
              <span className="chip">{state.prompt.algorithm}</span>
              <code>{state.prompt.fingerprint}</code>
            </div>
            {state.prompt.others && <p className="hint warn-text">{t("term.verify.others")}</p>}
            <div className="term-actions">
              <button type="button" className="btn" disabled={busy} onClick={() => void answer(false)}>
                {t("action.cancel")}
              </button>
              <button type="button" className="btn primary" disabled={busy} onClick={() => void answer(true)} autoFocus>
                {t("term.verify.trust")}
              </button>
            </div>
          </div>
        </div>
      )}

      {(state.kind === "closed" || broken) && (
        <div className="term-ended">
          {broken ? (
            <Alert message={broken} />
          ) : state.kind === "closed" && state.error ? (
            <Alert message={state.error} />
          ) : (
            <span className="term-ended-text">
              <span className="chip dot">{t("term.ended")}</span>
              {state.kind === "closed" && state.exit !== null && <span className="hint">{t("term.exit", { code: state.exit })}</span>}
            </span>
          )}
          <div className="term-actions">
            <button type="button" className="btn" onClick={() => void closeTab(tab.key)}>
              {t("term.closeTab")}
            </button>
            <button type="button" className="btn primary" onClick={() => reconnectTab(tab.key)}>
              <Icon name="sync" size={13} />
              {t("term.reconnect")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/// A tab's state as the strip shows it: a dot's tone and a word.
export function stateTone(tab: Tab): "ok" | "warn" | "bad" | "" {
  switch (tab.state.kind) {
    case "open":
      return "ok";
    case "closed":
      return tab.state.error ? "bad" : "";
    default:
      return "warn";
  }
}

export function stateWord(tab: Tab): string {
  switch (tab.state.kind) {
    case "open":
      return t("term.state.open");
    case "closed":
      return tab.state.error ? tError(tab.state.error) : t("term.ended");
    case "verify":
      return t("term.state.verify");
    case "authenticating":
      return t("term.authenticating");
    default:
      return t("term.state.connecting");
  }
}
