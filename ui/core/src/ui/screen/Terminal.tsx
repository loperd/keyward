// A terminal the core draws for any plugin: `open` gives a stream, and the
// plugin's `read`, `write`, `resize` and `close` carry it — over whatever
// road the backend has to the plugin (sealed, in the desktop app), the output
// on its own lane so that a long poll never holds the keystrokes back. What
// the shell prints goes straight into the terminal, never into React's
// state. The terminal's code is loaded when one is first drawn.
import "@xterm/xterm/css/xterm.css";
import { useEffect, useMemo, useRef, useState } from "react";
import { t } from "../../i18n";
import { type TerminalOps, PluginLane, StreamState } from "../../plugin/screen";
import { ThemeChoice } from "../../settings/types";
import { Icon } from "../Icons";
import { Spinner } from "../marks";
import { useScreen } from "./context";

function b64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function unb64(text: string): Uint8Array {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/// How long a read waits on the plugin for output.
const WAIT_MS = 15000;

/// The theme's colours, as the terminal takes them.
function theme() {
  const css = getComputedStyle(document.documentElement);
  const token = (name: string) => css.getPropertyValue(name).trim();
  const set = document.documentElement.dataset.theme;
  const light = set === ThemeChoice.Light || (set !== ThemeChoice.Dark && window.matchMedia("(prefers-color-scheme: light)").matches);
  const ground = token("--tier-lo");
  const accent = token("--sky");
  return {
    background: ground,
    foreground: token("--text"),
    cursor: accent,
    cursorAccent: ground,
    selectionBackground: `color-mix(in srgb, ${accent} 33%, transparent)`,
    black: light ? token("--text") : token("--raise"),
    red: token("--rose"),
    green: token("--mint"),
    yellow: token("--amber"),
    blue: token("--blue-hi"),
    magenta: accent,
    cyan: token("--cyan"),
    white: light ? token("--faint") : token("--dim"),
    brightBlack: token("--faint"),
    brightRed: token("--rose"),
    brightGreen: token("--mint"),
    brightYellow: token("--amber"),
    brightBlue: token("--blue-hi"),
    brightMagenta: accent,
    brightCyan: token("--cyan"),
    brightWhite: token("--text"),
  };
}

/// Every change of the theme: the system's, or one chosen by hand.
function onTheme(change: () => void): () => void {
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  media.addEventListener("change", change);
  const watcher = new MutationObserver(change);
  watcher.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "style"] });
  return () => {
    media.removeEventListener("change", change);
    watcher.disconnect();
  };
}

export function Terminal({ ops: given }: { ops: TerminalOps }) {
  const { call, reader } = useScreen();
  const host = useRef<HTMLDivElement>(null);
  const [state, setState] = useState(StreamState.Connecting);
  const [error, setError] = useState<string | null>(null);
  const [round, setRound] = useState(0);
  // The same terminal declared again (its page asked again) is the same
  // shell: only a terminal of other operations starts a new one.
  const sig = JSON.stringify(given);
  const ops = useMemo(() => given, [sig]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    let alive = true;
    let stream: string | null = null;
    let cleanup: (() => void) | null = null;
    setState(StreamState.Connecting);
    setError(null);
    const fail = (e: unknown) => {
      if (!alive) return;
      setError(e instanceof Error ? e.message : String(e));
      setState(StreamState.Closed);
    };

    void Promise.all([import("@xterm/xterm"), import("@xterm/addon-fit")]).then(([{ Terminal: Xterm }, { FitAddon }]) => {
      const el = host.current;
      if (!alive || !el) return;
      const term = new Xterm({ fontFamily: getComputedStyle(document.documentElement).getPropertyValue("--mono").trim(), fontSize: 12, cursorBlink: true, theme: theme() });
      const untheme = onTheme(() => {
        term.options.theme = theme();
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(el);
      fit.fit();

      const pump = async () => {
        let cursor = 0;
        while (alive && stream) {
          const r = reader.chunk((await call(ops.read, { stream, cursor, wait_ms: WAIT_MS }, PluginLane.Output)).data, ops.read);
          if (!alive) return;
          if (r.data) term.write(unb64(r.data));
          cursor = r.cursor;
          setState(r.state);
          if (r.state === StreamState.Closed) {
            if (r.error) setError(r.error);
            return;
          }
        }
      };

      call(ops.open.op, { ...((ops.open.payload as Record<string, unknown> | null) ?? {}), cols: term.cols, rows: term.rows }, PluginLane.Input)
        .then((r) => {
          stream = reader.stream(r.data, ops.open.op);
          if (!alive) {
            void call(ops.close, { stream }, PluginLane.Input).catch(console.error);
            return;
          }
          return pump();
        })
        .catch(fail);

      const typing = term.onData((d) => {
        if (stream) call(ops.write, { stream, data: b64(d) }, PluginLane.Input).catch(fail);
      });
      const observer = new ResizeObserver(() => {
        fit.fit();
        if (stream) call(ops.resize, { stream, cols: term.cols, rows: term.rows }, PluginLane.Input).catch(fail);
      });
      observer.observe(el);
      term.focus();
      cleanup = () => {
        observer.disconnect();
        typing.dispose();
        untheme();
        term.dispose();
      };
    }, fail);

    return () => {
      alive = false;
      if (stream) void call(ops.close, { stream }, PluginLane.Input).catch(console.error);
      cleanup?.();
    };
  }, [call, reader, ops, round]);

  return (
    <div className="kw-term">
      <div className="kw-term-host" ref={host} />
      {state === StreamState.Connecting && (
        <div className="kw-term-over">
          <Spinner />
          {t("scr.connecting")}
        </div>
      )}
      {state === StreamState.Closed && (
        <div className="kw-term-end">
          <Icon name={error ? "state" : "check"} />
          <span className="kw-term-why">{error ?? t("scr.ended")}</span>
          <button type="button" className="kw-btn kw-quiet" onClick={() => setRound((n) => n + 1)}>
            <Icon name="refresh" />
            {t("scr.again")}
          </button>
        </div>
      )}
    </div>
  );
}
