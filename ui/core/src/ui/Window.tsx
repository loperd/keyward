// The window: the strip over the stage of sheets, and the keyboard. Arrows
// walk the columns, typing anywhere goes to the line, ⌘K opens it, ⌘[ ⌘] walk
// the history, Space looks quickly, Esc steps back out of a preview, a map or
// a look.
import type { SecretFormHandle } from "./SecretForm";
import { secretsProblem, withSecrets } from "../verbs/account";
import { SETTINGS_ID } from "../settings/pages";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { answerOf, columns, fold, type Column, AnswerKind, ColumnType } from "../path/query";
import { usePath } from "../path/store";
import type { Effect } from "../verbs/spec";
import { Columns } from "./Columns";
import { calmOrder, openFound } from "./CalmList";
import { Inspector } from "./Inspector";
import { QuickLook } from "./QuickLook";
import { Strip, sectionLines } from "./Strip";
import { readyEffect, type RunState, RunPhase } from "./VerbPreview";
import { useCore } from "./marks";
import { useWrites } from "./writes-context";
import { tokenPx } from "./tokens";
import type { LineHandle } from "./PathLine";
import { useBusy, type Activity } from "./activity";
import { t, text } from "../i18n";
import { ToastKind } from "./toasts";
import { ScreenOverlays, useScreenView } from "./screen/Sheet";

/// The thin bar under the strip while a call a person set going is in
/// flight. It is always there, so its coming and going fade.
function ActivityBar({ activity }: { activity: Activity }) {
  const busy = useBusy(activity);
  return <div className={`kw-activity${busy ? " kw-on" : ""}`} role="progressbar" aria-hidden={!busy} aria-busy={busy} aria-label={t("ui.working")} />;
}

/// Effects whose sheet moves on when they succeed: the preview is gone
/// before it could say "done", so a toast says it.
const movesOn = (e: Effect) => "org" in e || "folder" in e;

export type WindowProps = {
  name: string;
  syncedAt: number;
  version: number;
  /// Runs a verb's effect; resolves to whether anything was changed.
  perform: (e: Effect) => Promise<boolean>;
  /// Words to type into the line once the window is up (the stand's
  /// "typing" screen).
  startTyping?: string | undefined;
};

export function Window({ name, syncedAt, version, perform, startTyping }: WindowProps) {
  const core = useCore();
  const writes = useWrites();
  const { query, store } = core;
  const snap = usePath(store);
  const st = snap.state;
  const line = useRef<LineHandle>(null);
  const stage = useRef<HTMLElement>(null);
  const [stageW, setStageW] = useState(0);
  const [winW, setWinW] = useState(() => window.innerWidth);
  const [lens, setLens] = useState(false);
  const [menu, setMenu] = useState(false);
  const [lsel, setLsel] = useState(0);
  const [mapHover, setMapHover] = useState<string | null>(null);
  const [run, setRun] = useState<{ line: string; state: RunState }>({ line: "", state: { phase: RunPhase.Idle } });
  const runState: RunState = run.line === snap.line ? run.state : { phase: RunPhase.Idle };

  useLayoutEffect(() => {
    const el = stage.current!;
    const ro = new ResizeObserver(() => {
      setStageW(el.clientWidth);
      setWinW(window.innerWidth);
    });
    ro.observe(el);
    setStageW(el.clientWidth);
    return () => ro.disconnect();
  }, []);
  useEffect(() => {
    if (startTyping !== undefined) {
      const id = setTimeout(() => line.current?.focus(startTyping), 200);
      return () => clearTimeout(id);
    }
  }, [startTyping]);
  // A new line starts the calm list at its top and forgets the pointer.
  useEffect(() => {
    setLsel(0);
    setMapHover(null);
  }, [snap.line]);

  let cols = columns(query, st.segs, st.map);
  const answer = answerOf(st, cols);
  if (answer.kind === AnswerKind.List) cols = cols.slice(0, -1);
  const n = cols.length;
  const W = { col: tokenPx("--col-w"), spine: tokenPx("--spine"), insp: tokenPx("--insp-max"), narrow: tokenPx("--narrow") };
  const open = fold(n, { map: !!st.map, narrow: winW < W.narrow, fits: (max) => (n - max) * W.spine + max * W.col + W.insp <= stageW, shown: snap.shown });
  const used = open.reduce((s, o) => s + (o ? W.col : W.spine), 0);
  const focus = Math.min(snap.focus, Math.max(0, n - 1));
  const obj = store.object();
  // A plugin's screen, drawer or dialogue over the page that is shown; those
  // over another page go when the window steps away from it.
  const docId = answer.kind === AnswerKind.Document ? (answer.id ?? "root") : null;
  const screenView = useScreenView(core.screens, docId);
  useEffect(() => core.screens.only(docId), [core.screens, docId]);

  const secretForm = useRef<SecretFormHandle>(null);
  const confirm = useCallback((): boolean => {
    const ready = readyEffect(core);
    if (!ready || runState.phase === RunPhase.Running || runState.phase === RunPhase.Done) return false;
    let e = ready.effect;
    const at = snap.line;
    // A verb with secret fields takes what was typed now, and only now: the
    // fields are emptied as they are read, and a mistake is said, not sent.
    if (ready.secrets) {
      const form = secretForm.current;
      if (!form) return false;
      const typed = form.take();
      const problem = secretsProblem(ready.secrets, typed);
      if (problem) {
        setRun({ line: at, state: { phase: RunPhase.Failed, reason: t(problem) } });
        return true;
      }
      e = withSecrets(e, typed);
    }
    setRun({ line: at, state: { phase: RunPhase.Running } });
    (writes?.perform(e) ?? perform(e)).then(
      (changed) => {
        if (movesOn(e)) core.toast(ToastKind.Ok, t("ui.toast.done", { what: text(ready.title) }));
        setRun((r) => (r.line === at ? { line: at, state: { phase: RunPhase.Done, changed } } : r));
      },
      (err: unknown) => setRun((r) => (r.line === at ? { line: at, state: { phase: RunPhase.Failed, reason: err instanceof Error ? err.message : String(err) } } : r)),
    );
    return true;
  }, [core, perform, writes, runState.phase, snap.line]);

  const onMapHover = useCallback((id: string | null) => setMapHover(id), []);
  const onRowHover = useCallback((id: string | null) => {
    const s = store.get().state;
    setMapHover(s.map && id && query.mapHas(s.map, id) ? id : null);
  }, [store, query]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey;
      const k = e.key.toLowerCase();
      if (meta && k === "k") {
        e.preventDefault();
        line.current?.focus();
        return;
      }
      if (meta && e.key === "[") {
        e.preventDefault();
        store.back();
        return;
      }
      if (meta && e.key === "]") {
        e.preventDefault();
        store.forward();
        return;
      }
      if (meta && k === "l") {
        e.preventDefault();
        store.verb("lock");
        return;
      }
      if (meta && e.key === "," && core.dir.has(SETTINGS_ID)) {
        e.preventDefault();
        store.go(SETTINGS_ID);
        return;
      }
      if (meta && /^[1-9]$/.test(e.key)) {
        const s = sectionLines(core)[Number(e.key) - 1];
        if (s) {
          e.preventDefault();
          store.commit(s.line);
        }
        return;
      }
      const active = document.activeElement;
      // Escape in a field of a plugin's drawer or dialogue closes it — but
      // never in a terminal, whose shell has its own use for the key.
      if (e.key === "Escape" && docId && active instanceof HTMLElement && active.closest(".kw-dialog, .kw-drawer") && !active.closest(".kw-term")) {
        e.preventDefault();
        core.screens.closeTop(docId);
        return;
      }
      if (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement || active instanceof HTMLSelectElement) return;
      if (menu) {
        if (e.key === "Escape") setMenu(false);
        return;
      }
      const s = store.get().state;
      if (e.key === "Escape") {
        if (lens) return setLens(false);
        // A plugin's dialogue, drawer and screen close first, the topmost
        // first.
        if (docId && core.screens.closeTop(docId)) {
          e.preventDefault();
          return;
        }
        if (s.verb !== null) return store.verb(null);
        if (s.map) return store.closeMap();
        // Nothing left to close: Escape goes back, as the strip's arrow does.
        if (store.get().canBack) {
          e.preventDefault();
          store.back();
        }
        return;
      }
      // A dialogue is modal: the path does not move under it.
      if (docId && core.screens.get(docId)?.dialog) return;
      if (e.key === "Enter" && s.verb !== null) {
        e.preventDefault();
        confirm();
        return;
      }
      if (e.key === "Enter" && s.map && obj && query.mapHas(s.map, obj)) {
        e.preventDefault();
        store.commitState({ segs: query.dir.node(obj).home.map((x) => ({ id: x })), map: null, verb: null, arg: "" });
        return;
      }
      if (e.key === " ") {
        e.preventDefault();
        if (obj) setLens((v) => !v);
        return;
      }
      if (meta || e.altKey) return;
      if (answer.kind === AnswerKind.List) {
        // The calm list may draw only the rows in sight: what it holds is
        // read from the query, not from the page.
        const found = calmOrder(query, answer.column as Extract<Column, { type: ColumnType.Results }>);
        const count = found.length;
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          setLsel((i) => Math.min(count - 1, Math.max(0, i + (e.key === "ArrowDown" ? 1 : -1))));
          return;
        }
        if (e.key === "Enter") {
          const id = found[lsel];
          if (id) openFound(store, id);
          return;
        }
      }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        store.move(e.key === "ArrowDown" ? 1 : -1);
        return;
      }
      if (e.key === "ArrowRight") {
        e.preventDefault();
        store.right();
        return;
      }
      if (e.key === "ArrowLeft") {
        e.preventDefault();
        store.left();
        return;
      }
      if (e.key === "Backspace") {
        e.preventDefault();
        store.drop();
        return;
      }
      // Type to query: any printable key starts the line, and lands in it.
      if (e.key.length === 1) line.current?.focus();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [core, store, query, menu, lens, confirm, answer.kind, lsel, obj, docId]);

  // A look at nothing closes.
  useEffect(() => {
    if (!obj) setLens(false);
  }, [obj]);

  return (
    <div className="kw-window">
      <Strip ref={line} name={name} syncedAt={syncedAt} menu={menu} setMenu={setMenu} onConfirm={confirm} />
      <main className="kw-stage" ref={stage}>
        <ActivityBar activity={core.activity} />
        <Columns cols={cols as Column[]} open={open} widths={W} focus={focus} lit={mapHover} onHover={onRowHover} />
        <Inspector answer={answer} run={runState} onRun={() => confirm()} lsel={lsel} mapHover={mapHover} onMapHover={onMapHover} version={version} secretForm={secretForm} />
        {lens && obj && <QuickLook id={obj} left={used} onClose={() => setLens(false)} />}
        {docId && screenView && (screenView.drawer || screenView.dialog) && <ScreenOverlays node={docId} view={screenView} />}

      </main>
    </div>
  );
}
