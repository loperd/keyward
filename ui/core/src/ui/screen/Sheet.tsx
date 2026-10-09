// A plugin's declared screen in the window: drawn in its place's page's
// stead, the drawer on the right over the sheet, the dialogue over the
// stage. The screen is asked for its route when it is shown and again when
// it says so (a scan under way) or a reply asks; the last answer stays
// through a refusal, which is said over it.
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { t, text, type Text } from "../../i18n";
import { LeadTile } from "../../doc/spec";
import { type ScreenPage, refusalText } from "../../plugin/screen";
import { Icon } from "../Icons";
import { IconButton, Mark, Tile, useCore } from "../marks";
import { Level } from "../../model/types";
import { DocSkeleton } from "../Loading";
import { ScreenContext, useReader, useScreenCtx, useWords } from "./context";
import { ButtonView, ChipView, Nodes } from "./Nodes";
import type { ScreenStore, ScreenView } from "./store";
import "../sheet.css";
import "../edit.css";
import "./screen.css";

/// What is open of plugins' screens over a node, as it changes.
export function useScreenView(screens: ScreenStore, node: string | null): ScreenView | null {
  return useSyncExternalStore(
    useCallback((l: () => void) => screens.subscribe(l), [screens]),
    () => (node ? screens.get(node) : null),
  );
}

/// A value (a host, a namespace) is set in the machines' face; words are not.
const valueClass = (t: Text) => ("raw" in t ? "mono" : undefined);

/// The least a screen is asked again after, whatever it asks.
const MIN_REFRESH_MS = 500;

/// The page a plugin gives for a route.
function usePage(plugin: string, route: string, epoch: number) {
  const { backend } = useCore();
  const reader = useReader(plugin);
  const words = useWords(plugin);
  const [page, setPage] = useState<ScreenPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [again, setAgain] = useState(0);
  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let every: number | undefined;
    // A screen that asks to be asked again goes on being asked through a
    // refused answer: the last page stays, the refusal is said over it.
    const load = () => {
      if (!backend.pluginView) {
        setError(`this app cannot show the plugin "${plugin}"'s screens`);
        return;
      }
      backend
        .pluginView(plugin, route)
        .then((raw) => {
          if (!alive) return;
          const p = reader.page(raw, route);
          setPage(p);
          setError(null);
          every = p.refreshMs;
        })
        .catch((e: unknown) => {
          if (!alive) return;
          console.error(e);
          setError(text(refusalText(plugin, words, e)));
        })
        .finally(() => {
          if (alive && every) timer = setTimeout(load, Math.max(MIN_REFRESH_MS, every));
        });
    };
    load();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [backend, reader, plugin, route, epoch, again]);
  return { page, error, retry: () => setAgain((n) => n + 1) };
}

/// A refusal said over what a screen still shows.
function Refused({ error, retry }: { error: string; retry: () => void }) {
  return (
    <div className="salert t-bad srefused" role="alert">
      <Mark level={Level.Critical} words={error} />
      <button type="button" className="btn quiet" onClick={retry}>
        <Icon name="refresh" />
        {t("scr.retry")}
      </button>
    </div>
  );
}

/// The screen a place opened, in its page's stead.
export function ScreenSheet({ node, view }: { node: string; view: ScreenView & { route: string } }) {
  const core = useCore();
  const ctx = useScreenCtx(node, view.plugin, view.epoch);
  const { page, error, retry } = usePage(view.plugin, view.route, view.epoch);
  const n = core.dir.node(node);
  const close = () => core.screens.patch(node, view.plugin, { route: null });
  const title: Text = page?.title ?? n.name;
  const primary = page?.actions.find((b) => b.primary && b.label);
  const rest = page?.actions.filter((b) => b !== primary) ?? [];
  return (
    <ScreenContext.Provider value={ctx}>
      <header className="hero shero">
        <Tile lead={{ tile: LeadTile.Node, id: node }} xl />
        <div className="hero-t">
          <h1 className={`h1${n.mono && !page?.title ? " mono" : ""}`}>{text(title)}</h1>
          <div className="place">
            <a onClick={close}>{text(n.name)}</a>
            {page?.subtitle && (
              <>
                <span className="sl">·</span>
                <span className={valueClass(page.subtitle)}>{text(page.subtitle)}</span>
              </>
            )}
          </div>
          {page && page.chips.length > 0 && (
            <div className="state">
              {page.chips.map((c, i) => (
                <ChipView key={i} chip={c} />
              ))}
            </div>
          )}
          <div className="acts">
            {primary && <ButtonView b={primary} />}
            {page?.crumb && <IconButton icon="back" tip={text(page.crumb.label)} onClick={() => void ctx.run(page.crumb!.action)} />}
            {rest.map((b, i) => (
              <ButtonView key={i} b={b.label ? { ...b, label: undefined, icon: b.icon ?? "verb" } : b} />
            ))}
            <IconButton icon="close" tip={t("scr.close")} onClick={close} />
          </div>
        </div>
      </header>
      {error && <Refused error={error} retry={retry} />}
      {page ? <div className="sbody">{<Nodes nodes={page.body} />}</div> : !error && <DocSkeleton rows={4} />}
    </ScreenContext.Provider>
  );
}

/// The head of a drawer or a dialogue: its icon, title and words, its
/// actions, and the close.
function OverHead({ page, onClose }: { page: ScreenPage; onClose: () => void }) {
  return (
    <header className="ohead">
      {page.icon && <Icon name={page.icon} className="ohead-ic" />}
      <span className="ohead-t">
        <b>{page.title ? text(page.title) : ""}</b>
        {page.subtitle && <span className={valueClass(page.subtitle)}>{text(page.subtitle)}</span>}
      </span>
      {page.chips.map((c, i) => (
        <ChipView key={i} chip={c} />
      ))}
      <span className="ohead-a">
        {page.actions.map((b, i) => (
          <ButtonView key={i} b={b} />
        ))}
        <IconButton icon="close" tip={t("scr.close")} onClick={onClose} className="tip-l" />
      </span>
    </header>
  );
}

/// The drawer and the dialogue over a node, where it has any.
export function ScreenOverlays({ node, view }: { node: string; view: ScreenView }) {
  const { screens } = useCore();
  const ctx = useScreenCtx(node, view.plugin, view.epoch);
  return (
    <ScreenContext.Provider value={ctx}>
      {view.drawer && (
        <aside className="drawer" role="dialog" aria-label={view.drawer.title ? text(view.drawer.title) : undefined}>
          <OverHead page={view.drawer} onClose={() => screens.patch(node, view.plugin, { drawer: null })} />
          <div className="obody">
            <Nodes nodes={view.drawer.body} />
          </div>
        </aside>
      )}
      {view.dialog && (
        <div className="dveil" onMouseDown={(e) => e.target === e.currentTarget && screens.patch(node, view.plugin, { dialog: null })}>
          <div className="dialog" role="dialog" aria-modal="true" aria-label={view.dialog.title ? text(view.dialog.title) : undefined}>
            <OverHead page={view.dialog} onClose={() => screens.patch(node, view.plugin, { dialog: null })} />
            <div className="obody">
              <Nodes nodes={view.dialog.body} />
            </div>
          </div>
        </div>
      )}
    </ScreenContext.Provider>
  );
}
