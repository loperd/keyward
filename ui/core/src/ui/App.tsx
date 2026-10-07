// The window over a backend: what both apps mount. Until the vault is open
// it shows the gate (sign in, a second factor, unlock); then it reads the
// session, the
// catalogue and the plugins' places, builds the graph and the line over them,
// rebuilds both whenever the backend says something changed, and keeps a
// person's saved places. Trash and restore are optimistic: the change shows
// at once and is taken back if the backend refuses. When the session closes
// (a lock, a logout) everything of the vault is let go at once: the
// catalogue, the graph, the query, the path and its history, the places held
// in memory (see SessionHold).
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import "./theme.css";
import "./base.css";
import "./window.css";
import "./columns.css";
import "./inspector.css";
import "./map.css";
import { type Backend, type Session, SessionState } from "../backend";
import { t } from "../i18n";
import type { Catalog } from "../model/types";
import { Directory, type Contribution } from "../path/directory";
import { DEFAULT_PLACES, placeFor, type Place, type PlaceStore } from "../path/places";
import { Query } from "../path/query";
import { CORE_VERBS } from "../verbs/core";
import type { Effect } from "../verbs/spec";
import { Gate } from "./Gate";
import { ICONS, Icon } from "./Icons";
import { CoreContext, useLang, type Core } from "./marks";
import { RepromptPrompt } from "./RepromptPrompt";
import { PairPrompt } from "./Extensions";
import { SessionHold } from "./session-hold";
import { Window } from "./Window";
import { WritesProvider } from "./writes-context";
import { RenderGuard } from "./RenderGuard";
import { withWriteVerbs } from "../verbs/writes";
import type { Writes } from "../writes";
import { Activity, tracked } from "./activity";
import { copiedWords } from "./act";
import { Toasts, ToastKind } from "./toasts";
import { Toaster } from "./Toaster";
import { LoadPhase, Loading } from "./Loading";
import { SettingsContext, type SettingsHold } from "./settings-context";
import { SettingsPage, SETTINGS_ID } from "../settings/pages";
import type { AppSettings, SettingsPatch, UnlockState } from "../settings/types";
import { ACCOUNT_VERBS } from "../verbs/account";
import { type FillContext, fillVerb } from "../verbs/fill";
import { applyLook } from "../settings/apply";

export type AppProps = {
  backend: Backend;
  /// The line to start on (the URL's).
  line?: string;
  /// Told every committed line, to keep it in the URL.
  onLine?: (line: string) => void;
  /// Places the app offers beyond the window's own.
  places?: Place[];
  /// Where a person's places are kept across sessions. A place's name and
  /// line are vault data (an item's name, the words searched for), so by
  /// default they are kept nowhere but in memory, and go when the session
  /// closes; only the stand hands in the browser's storage, for its demo.
  /// Pass one stable object for the App's life.
  placeStore?: PlaceStore;
  /// Words typed into the line once it is up.
  startTyping?: string;
  /// Whether the locked gate asks for Touch ID by itself (default yes).
  autoBiometric?: boolean;
  /// How the app changes a vault; without it nothing is offered to edit or
  /// make.
  writes?: Writes;
};

type Unlocked = Extract<Session, { state: SessionState.Unlocked }>;
type Closed = Exclude<Session, { state: SessionState.Unlocked }>;
type Loaded = { session: Unlocked; catalog: Catalog; contributions: Contribution[]; at: number };

export function App({ backend, line = "", onLine, places: extra = [], placeStore, startTyping, autoBiometric = true, writes }: AppProps) {
  useLang();
  const hold = useMemo(() => new SessionHold(backend, placeStore), [backend, placeStore]);
  useEffect(() => () => hold.close(), [hold]);
  // The calls a person set going are counted while they run (the activity
  // bar); the session's own reads in `load` are not.
  const activity = useMemo(() => new Activity(), []);
  const toasts = useMemo(() => new Toasts(), []);
  useEffect(() => () => toasts.clear(), [toasts]);
  const calls = useMemo(() => tracked(backend, activity), [backend, activity]);
  const changes = useMemo(() => (writes ? tracked(writes, activity) : null), [writes, activity]);
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  // The session while the vault is not open: the gate stands instead of the
  // window, and nothing of the vault is kept meanwhile.
  const [closed, setClosed] = useState<Closed | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  // What the boot screen waits for, until the window is first up.
  const [phase, setPhase] = useState(LoadPhase.Session);
  const up = useRef(false);
  const [version, setVersion] = useState(0);
  // Items whose trash state is shown before the backend has confirmed it.
  const [overlay, setOverlay] = useState<Map<string, boolean>>(new Map());
  const [revealTick, setRevealTick] = useState(0);

  const report = useCallback((e: unknown) => {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(e);
    toasts.push(ToastKind.Error, msg);
  }, [toasts]);

  // The app's settings, where it keeps any: no vault data, so they are read
  // at once, before the gate, and the theme and language follow them from
  // the first frame.
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [settingsFailed, setSettingsFailed] = useState<string | null>(null);
  useEffect(() => {
    if (!backend.settings) return;
    let live = true;
    backend.settings().then(
      (s) => live && setSettings(s),
      (e: unknown) => {
        if (!live) return;
        console.error(e);
        setSettingsFailed(e instanceof Error ? e.message : String(e));
      },
    );
    return () => {
      live = false;
    };
  }, [backend]);
  useEffect(() => {
    if (settings) applyLook(settings);
  }, [settings]);
  const patchSettings = useCallback(
    async (p: SettingsPatch) => {
      if (!calls.setSettings) throw new Error("this app keeps no settings");
      setSettings(await calls.setSettings(p));
    },
    [calls],
  );
  // How the account opens here besides the master password: read once the
  // vault is open, and again after each change of it.
  const [unlock, setUnlock] = useState<UnlockState | null>(null);
  const [accountTick, setAccountTick] = useState(0);
  // What was in front at ⌘⇧L: `> fill` types into it.
  const [fillCtx, setFillCtx] = useState<FillContext | null>(null);
  const readUnlock = useCallback(() => {
    if (!backend.unlockState) return;
    backend.unlockState().then(setUnlock, report);
  }, [backend, report]);
  const settingsHold: SettingsHold = useMemo(() => ({ settings, failed: settingsFailed, patch: patchSettings, unlock, accountTick }), [settings, settingsFailed, patchSettings, unlock, accountTick]);
  const pages = useMemo(() => (backend.settings ? [...(backend.profile ? [SettingsPage.Account] : []), SettingsPage.Security, ...(backend.caps.biometric ? [SettingsPage.Unlock] : []), ...(backend.extensions ? [SettingsPage.Browsers] : []), SettingsPage.App] : []), [backend]);

  // A person's places: read when the vault opens, dropped when it closes.
  const [mine, setMine] = useState<Place[]>([]);
  const places = useMemo(() => [...DEFAULT_PLACES, ...extra, ...mine], [extra, mine]);

  // Loads overlap (a sync and a lock announced together); only the latest
  // one's answer is taken.
  const seq = useRef(0);
  const load = useCallback(async () => {
    const n = ++seq.current;
    const session = await backend.session();
    if (n !== seq.current) return;
    if (session.state !== SessionState.Unlocked) {
      up.current = false;
      hold.close();
      setClosed(session);
      setLoaded(null);
      setMine([]);
      setRevealTick(0);
      setOverlay((o) => (o.size ? new Map() : o));
      return;
    }
    // Reading the vault again after a sync or a write is shown like the call
    // that caused it: the bar runs until the window has the new catalogue.
    const end = activity.begin();
    if (!up.current) setPhase(LoadPhase.Catalog);
    const reading = backend.catalog();
    // Once the catalogue is in, what is left is the plugins' places. A
    // refusal is not handled here: Promise.all below carries it.
    if (!up.current) reading.then(() => n === seq.current && !up.current && setPhase(LoadPhase.Places), () => undefined);
    const [catalog, contributions] = await Promise.all([reading, backend.contributions()]).finally(end);
    if (n !== seq.current) return;
    const opened = hold.opened(catalog, ICONS);
    if (opened) {
      // A report says which entry, never what it holds.
      for (const p of opened.problems) console.error(p);
      setMine(opened.places);
    }
    setClosed(null);
    if (!up.current) readUnlock();
    up.current = true;
    setLoaded({ session, catalog, contributions, at: Date.now() });
    setVersion((v) => v + 1);
    // What the backend now says is what stands: the overlay only covers
    // changes it has not answered yet.
    setOverlay((o) => {
      const next = new Map(o);
      for (const [id, del] of o) if (catalog.items.find((i) => i.id === id)?.deleted === del) next.delete(id);
      return next.size === o.size ? o : next;
    });
  }, [backend, hold, readUnlock]);
  const boot = useCallback(() => {
    load().catch((e: unknown) => setFailure(e instanceof Error ? e.message : String(e)));
  }, [load]);
  useEffect(() => {
    boot();
    return backend.subscribe(() => {
      load().catch(report);
    });
  }, [backend, load, boot, report]);
  const retry = useCallback(() => {
    setFailure(null);
    setPhase(LoadPhase.Session);
    boot();
  }, [boot]);

  const dir = useMemo(() => {
    if (!loaded) return null;
    for (const c of loaded.contributions) if (c.words) hold.registerWords(c.id, c.words);
    const catalog: Catalog = overlay.size ? { ...loaded.catalog, items: loaded.catalog.items.map((i) => (overlay.has(i.id) ? { ...i, deleted: overlay.get(i.id)! } : i)) } : loaded.catalog;
    return new Directory(catalog, loaded.contributions, { places, settings: pages });
  }, [loaded, overlay, places, hold, pages]);
  const query = useMemo(() => (dir && loaded ? new Query(dir, [...(writes ? withWriteVerbs(CORE_VERBS) : CORE_VERBS), ...(backend.account && dir.has(SETTINGS_ID) ? ACCOUNT_VERBS : []), ...(backend.fill ? [fillVerb(fillCtx)] : []), ...loaded.contributions.flatMap((c) => c.verbs ?? [])]) : null), [dir, loaded, writes, backend, fillCtx]);

  // The path lives in the hold, and goes with the session. A new graph is
  // read before anything draws from it: a step that vanished must drop out
  // of the path before a column asks for its node.
  const store = query ? hold.pathFor(query, line) : hold.dropPath();
  useEffect(() => {
    if (!store || !onLine) return;
    onLine(store.get().line);
    return store.subscribe(() => onLine(store.get().line));
  }, [store, onLine, query]);

  const perform = useCallback(
    async (e: Effect): Promise<boolean> => {
      if (!store) throw new Error("a verb ran before the window was up");
      if ("copy" in e) {
        // An item that asks for the master password again copies nothing
        // before it is given; giving up is no failure.
        if (await hold.reprompt.confirm(e.copy.itemId)) toasts.push(ToastKind.Copy, copiedWords(e.copy, await calls.copy(e.copy)));
        return true;
      }
      if ("lock" in e) {
        await calls.lock();
        return true;
      }
      if ("plugin" in e) {
        if (!calls.pluginAct) throw new Error(`this app cannot carry out the plugin "${e.plugin.plugin}"'s actions`);
        await calls.pluginAct(e.plugin);
        return true;
      }
      if ("sync" in e) {
        await calls.sync();
        return true;
      }
      if ("fill" in e) {
        if (!calls.fill || !calls.fillAccess || !calls.requestFillAccess) throw new Error("this app cannot type into other apps");
        // Without Accessibility nothing can be typed: the system is asked,
        // and the person is told where to switch it on.
        if (!(await calls.fillAccess())) {
          await calls.requestFillAccess();
          throw new Error(t("fill.noAccess"));
        }
        await calls.fill(e.fill.itemId, e.fill.mode);
        setFillCtx(null);
        return true;
      }
      if ("account" in e) {
        if (!calls.account) throw new Error("this app cannot change how the account opens");
        if (!e.account.secrets) throw new Error("an account's change ran without what was typed for it");
        const saved = await calls.account({ ...e.account, secrets: e.account.secrets });
        if (saved !== null) toasts.push(ToastKind.Ok, t("verb.acct.export.saved", { path: saved }));
        readUnlock();
        setAccountTick((n) => n + 1);
        return true;
      }
      if ("trash" in e || "restore" in e) {
        const ids = "trash" in e ? e.trash : e.restore;
        const del = "trash" in e;
        const before = store.get().state;
        // Step off the item first: its place is about to change.
        store.commitState({ segs: before.segs.slice(0, -1), map: null, verb: null, arg: "" });
        setOverlay((o) => new Map([...o, ...ids.map((id) => [id, del] as const)]));
        try {
          await (del ? calls.trash(ids) : calls.restore(ids));
        } catch (err) {
          setOverlay((o) => {
            const next = new Map(o);
            for (const id of ids) next.delete(id);
            return next;
          });
          report(new Error(t(del ? "ui.trashFailed" : "ui.restoreFailed", { reason: err instanceof Error ? err.message : String(err) })));
          throw err;
        }
        toasts.push(ToastKind.Ok, t(del ? "ui.toast.trashed" : "ui.toast.restored"));
        return true;
      }
      return false;
    },
    [calls, store, report, hold, toasts, readUnlock],
  );

  // ⌘⇧L: the window comes up on the items for the site in front.
  useEffect(() => {
    if (!backend.onAutofill || !store) return;
    return backend.onAutofill((ctx) => {
      setFillCtx(ctx);
      // The site's items, where a browser named the site; otherwise the
      // window stays where the person left it.
      if (ctx.domain) store.commit(ctx.domain);
      toasts.push(ToastKind.Info, t("fill.from", { app: ctx.app }));
    });
  }, [backend, store, toasts]);

  const savePlace = useCallback(() => {
    if (!query || !store) return;
    const p = placeFor(query, store.get().state);
    const next = [...mine.filter((x) => x.id !== p.id), p];
    setMine(next);
    if (!hold.savePlaces(next)) toasts.push(ToastKind.Info, t("ui.placeSessionOnly"));
  }, [query, store, mine, hold, toasts]);

  const core: Core | null = useMemo(
    () =>
      dir && query && store && loaded
        ? {
            dir,
            query,
            store,
            backend: calls,
            places,
            server: loaded.session.server,
            savePlace,
            report,
            revealAll: () => setRevealTick((n) => n + 1),
            revealTick,
            reprompt: hold.reprompt,
            activity,
            toast: (kind, text) => void toasts.push(kind, text),
          }
        : null,
    [dir, query, store, loaded, calls, places, savePlace, report, revealTick, hold, activity, toasts],
  );

  // The gate that opened the vault fades out over the window that came: its
  // last drawing ("Opening the vault…") is kept a moment over the window.
  const gateEl = useRef<Element | null>(null);
  const holdGate = useCallback((box: HTMLDivElement | null) => {
    if (box) gateEl.current = box.firstElementChild;
  }, []);
  const gateOpen = useRef(false);
  useLayoutEffect(() => {
    const was = gateOpen.current;
    gateOpen.current = !!closed;
    if (was && !closed && core && gateEl.current) fadeGateAway(gateEl.current);
    if (!closed) gateEl.current = null;
  }, [closed, core]);

  const toastEl = <Toaster toasts={toasts} />;
  // Until the first answer, and between an open session and its first
  // catalogue, the boot screen stands; it fades out over what came.
  const booting = !failure && !closed && !(core && loaded);
  // The boot screen keeps one place in the tree whatever stands under it,
  // so it can fade out over the gate or the window that came.
  const veil = <BootVeil on={booting} phase={phase} />;
  let content: ReactNode = null;
  if (failure) content = <LoadFailed reason={failure} onRetry={retry} />;
  else if (closed)
    content = (
      <>
        <div className="kw-gate-box" ref={holdGate}>
          <Gate key={closed.state} backend={backend} session={closed} onDone={load} autoBiometric={autoBiometric} />
        </div>
        {toastEl}
      </>
    );
  else if (core && loaded) {
    const s = loaded.session;
    content = (
      <CoreContext.Provider value={core}>
        <SettingsContext.Provider value={settingsHold}>
        <WritesProvider writes={changes}>
          <RenderGuard line={store?.get().line ?? ""} onBack={() => store?.commit("")}>
            <Window name={s.name ?? s.email} syncedAt={loaded.at} version={version} perform={perform} startTyping={startTyping} />
          </RenderGuard>
        </WritesProvider>
        </SettingsContext.Provider>
        <RepromptPrompt reprompt={hold.reprompt} />
        {backend.extensions && <PairPrompt />}
        {toastEl}
      </CoreContext.Provider>
    );
  }
  return (
    <>
      {content}
      {veil}
    </>
  );
}

/// What may hold a value typed into the gate: a fading copy never carries it.
const GATE_HELD = "input, textarea";

/// The gate's last drawing, let go by React, put back over the window to
/// fade out (--dur), emptied of every field and out of reach of the pointer,
/// the keyboard and a screen reader.
function fadeGateAway(gate: Element) {
  if (!(gate instanceof HTMLElement)) return;
  for (const n of gate.querySelectorAll(GATE_HELD)) n.remove();
  gate.classList.add("kw-gate-ghost");
  gate.setAttribute("aria-hidden", "true");
  gate.inert = true;
  const done = () => gate.remove();
  gate.addEventListener("animationend", (e) => {
    if (e.target === gate) done();
  });
  setTimeout(done, VEIL_MAX_MS);
  document.body.appendChild(gate);
}

/// The longest the boot screen stands over the window once what it waited
/// for has come: well past its fade (--dur).
const VEIL_MAX_MS = 1000;

/// The boot screen while `on`; once it is off, the same screen fading out
/// over what came (a cross-fade at --dur), then nothing.
function BootVeil({ on, phase }: { on: boolean; phase: LoadPhase }) {
  const [gone, setGone] = useState(!on);
  if (on && gone) setGone(false);
  // The fade's end lets it go; should no animation run at all (a page with
  // animations switched off), it goes all the same a moment later rather
  // than stand over the window.
  useEffect(() => {
    if (on || gone) return;
    const timer = setTimeout(() => setGone(true), VEIL_MAX_MS);
    return () => clearTimeout(timer);
  }, [on, gone]);
  if (gone) return null;
  return <Loading phase={phase} leaving={!on} onGone={() => setGone(true)} />;
}

/// A session that would not load: the window's strip, then the document's
/// gutters and type — what failed, why, and one way on.
function LoadFailed({ reason, onRetry }: { reason: string; onRetry: () => void }) {
  return (
    <div className="kw-window">
      <header className="kw-strip" data-tauri-drag-region="deep" />
      <main className="kw-stage">
        <section className="kw-insp">
          <div className="kw-doc kw-enter kw-load-failed" role="alert">
            <h1 className="kw-h1">{t("load.failedTitle")}</h1>
            <p>{t("ui.loadFailed", { reason })}</p>
            <div className="kw-acts">
              <button type="button" className="kw-btn kw-solid" onClick={onRetry} autoFocus>
                <Icon name="refresh" />
                {t("load.retry")}
              </button>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
