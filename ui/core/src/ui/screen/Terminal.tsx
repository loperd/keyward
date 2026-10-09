// A terminal the core draws for any plugin: `open` gives a stream, and the
// plugin's `read`, `write`, `resize` and `close` carry it — over whatever
// road the backend has to the plugin (sealed, in the desktop app), the output
// on its own lane so that a long poll never holds the keystrokes back. What
// the shell prints goes straight into the terminal, never into React's
// state. The terminal's code is loaded when one is first drawn.
import "@xterm/xterm/css/xterm.css";
import { useEffect, useMemo, useRef, useState } from "react";
import { t, text } from "../../i18n";
import { type Chunk, type TerminalOps, PluginLane, StreamState } from "../../plugin/screen";
import { Level } from "../../model/types";
import { ThemeChoice } from "../../settings/types";
import { Icon } from "../Icons";
import { IconButton, Mark, Spinner } from "../marks";
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
  const { call, reader, refusal } = useScreen();
  const host = useRef<HTMLDivElement>(null);
  // The stream the terminal is attached to: its question and its close are
  // answered outside the loop that reads it.
  const stream = useRef<string | null>(null);
  const [state, setState] = useState(StreamState.Connecting);
  const [ask, setAsk] = useState<Chunk["ask"] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [round, setRound] = useState(0);
  // The same terminal declared again (its page asked again) is the same
  // shell: only a terminal of other operations starts a new one.
  const sig = JSON.stringify(given);
  const ops = useMemo(() => given, [sig]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    let alive = true;
    let cleanup: (() => void) | null = null;
    stream.current = null;
    setState(StreamState.Connecting);
    setAsk(null);
    setError(null);
    const fail = (e: unknown) => {
      if (!alive) return;
      setError(text(refusal(e)));
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
        // The plugin's own cursor, sent back as it came; a stream attached
        // again starts from its beginning and replays what it kept.
        let cursor: unknown = 0;
        while (alive && stream.current) {
          const r = reader.chunk((await call(ops.read, { stream: stream.current, cursor, wait_ms: WAIT_MS }, PluginLane.Output)).data, ops.read);
          if (!alive) return;
          if (r.data) term.write(unb64(r.data));
          cursor = r.cursor;
          setState(r.state);
          setAsk(r.state === StreamState.Verify ? (r.ask ?? null) : null);
          if (r.state === StreamState.Closed) {
            if (r.error) setError(text(refusal(r.error)));
            return;
          }
        }
      };

      call(ops.open.op, { ...((ops.open.payload as Record<string, unknown> | null) ?? {}), cols: term.cols, rows: term.rows }, PluginLane.Input)
        .then((r) => {
          const id = reader.stream(r.data, ops.open.op);
          if (!alive) {
            if (!ops.keep) void call(ops.close, { stream: id }, PluginLane.Input).catch(console.error);
            return;
          }
          stream.current = id;
          // The size it has here, now that there is a stream to tell.
          void call(ops.resize, { stream: id, cols: term.cols, rows: term.rows }, PluginLane.Input).catch(fail);
          return pump();
        })
        .catch(fail);

      const typing = term.onData((d) => {
        const id = stream.current;
        if (id) call(ops.write, { stream: id, data: b64(d) }, PluginLane.Input).catch(fail);
      });
      const observer = new ResizeObserver(() => {
        fit.fit();
        const id = stream.current;
        if (id) call(ops.resize, { stream: id, cols: term.cols, rows: term.rows }, PluginLane.Input).catch(fail);
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
      // A stream kept outlives the terminal: it is attached again later.
      if (stream.current && !ops.keep) void call(ops.close, { stream: stream.current }, PluginLane.Input).catch(console.error);
      stream.current = null;
      cleanup?.();
    };
  }, [call, reader, refusal, ops, round]);

  const answer = (yes: boolean) => {
    const id = stream.current;
    if (!id || !ops.trust) return;
    setAsk(null);
    call(ops.trust, { stream: id, answer: yes }, PluginLane.Input).catch((e: unknown) => {
      setError(text(refusal(e)));
      setState(StreamState.Closed);
    });
  };
  const close = () => {
    const id = stream.current;
    if (!id) return;
    call(ops.close, { stream: id }, PluginLane.Input).catch((e: unknown) => setError(text(refusal(e))));
  };

  return (
    <div className="term">
      <div className="term-host" ref={host} />
      {ops.keep && state !== StreamState.Closed && (
        <span className="term-close">
          <IconButton icon="close" tip={t("scr.closeSession")} onClick={close} className="tip-l" />
        </span>
      )}
      {(state === StreamState.Connecting || state === StreamState.Authenticating) && (
        <div className="term-over">
          <Spinner />
          {t(state === StreamState.Authenticating ? "scr.authenticating" : "scr.connecting")}
        </div>
      )}
      {state === StreamState.Verify && ask && (
        <div className="term-over term-ask" role="alertdialog" aria-label={text(ask.text)}>
          <Mark level={Level.Warning} words={ask.text} />
          {ask.code && <code className="mono term-code">{ask.code}</code>}
          <span className="term-acts">
            <button type="button" className="btn quiet" onClick={() => answer(false)}>
              <Icon name="close" />
              {t("scr.refuse")}
            </button>
            <button type="button" className="btn solid" disabled={!ops.trust} onClick={() => answer(true)}>
              <Icon name="check" />
              {t("scr.trust")}
            </button>
          </span>
        </div>
      )}
      {state === StreamState.Closed && (
        <div className="term-end">
          <Icon name={error ? "state" : "check"} />
          <span className="term-why">{error ?? t("scr.ended")}</span>
          {!ops.keep && (
            <button type="button" className="btn quiet" onClick={() => setRound((n) => n + 1)}>
              <Icon name="refresh" />
              {t("scr.again")}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
