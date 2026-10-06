import "@xterm/xterm/css/xterm.css";
import { useEffect, useRef, useState } from "react";
import { Terminal as Xterm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { Icon, onThemeChange, terminalTheme } from "../ui";
import { t, tError } from "../i18n";
import { act, actOut } from "./channel";
import type { Action } from "./types";

type Chunk = { data: string; cursor: number; state: "connecting" | "open" | "closed"; error?: string | null };

function b64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function unb64(text: string): Uint8Array {
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/// A terminal the window draws for any plugin: `open` gives a stream, and the
/// plugin's `read`, `write`, `resize` and `close` carry it — all sealed, the
/// output on its own lane so a long poll never holds the keystrokes back.
export function Terminal({ plugin, open, read, write, resize, close }: { plugin: string; open: Action; read: string; write: string; resize: string; close: string }) {
  const host = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<"connecting" | "open" | "closed">("connecting");
  const [error, setError] = useState<string | null>(null);
  const [epoch, setEpoch] = useState(0);

  useEffect(() => {
    if (!host.current) return;
    // The theme's colours, and again whenever the theme changes.
    const term = new Xterm({ fontFamily: '"IBM Plex Mono", ui-monospace, monospace', fontSize: 12, cursorBlink: true, theme: terminalTheme() });
    const untheme = onThemeChange(() => {
      term.options.theme = terminalTheme();
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host.current);
    fit.fit();
    let alive = true;
    let stream: string | null = null;
    setState("connecting");
    setError(null);

    const pump = async () => {
      let cursor = 0;
      while (alive && stream) {
        try {
          const r = (await actOut(plugin, read, { stream, cursor, wait_ms: 15000 })).data as Chunk;
          if (!alive) return;
          if (r.data) term.write(unb64(r.data));
          cursor = r.cursor;
          setState(r.state);
          if (r.state === "closed") {
            if (r.error) setError(r.error);
            return;
          }
        } catch (e) {
          if (alive) {
            setError(String(e));
            setState("closed");
          }
          return;
        }
      }
    };

    const payload = { ...((open.payload as Record<string, unknown>) ?? {}), cols: term.cols, rows: term.rows };
    act(plugin, open.op, payload)
      .then((r) => {
        stream = (r.data as { stream: string }).stream;
        if (!alive) {
          void act(plugin, close, { stream }).catch(() => undefined);
          return;
        }
        void pump();
      })
      .catch((e) => {
        setError(String(e));
        setState("closed");
      });

    const typing = term.onData((d) => {
      if (stream) void act(plugin, write, { stream, data: b64(d) }).catch(() => undefined);
    });
    const observer = new ResizeObserver(() => {
      fit.fit();
      if (stream) void act(plugin, resize, { stream, cols: term.cols, rows: term.rows }).catch(() => undefined);
    });
    observer.observe(host.current);
    term.focus();

    return () => {
      alive = false;
      observer.disconnect();
      typing.dispose();
      if (stream) void act(plugin, close, { stream }).catch(() => undefined);
      untheme();
      term.dispose();
    };
  }, [plugin, open, read, write, resize, close, epoch]);

  return (
    <div className="dv-terminal">
      <div className="dv-terminal-host" ref={host} />
      {state === "connecting" && (
        <div className="dv-terminal-over">
          <span className="dv-spinner" />
          {t("dv.connecting")}
        </div>
      )}
      {state === "closed" && (
        <div className="dv-terminal-end">
          <Icon name={error ? "warn" : "check"} size={13} />
          <span>{error ? tError(error) : t("dv.ended")}</span>
          <span className="grow" />
          <button type="button" className="btn small" onClick={() => setEpoch((n) => n + 1)}>
            <Icon name="sync" size={13} />
            {t("dv.again")}
          </button>
        </div>
      )}
    </div>
  );
}
