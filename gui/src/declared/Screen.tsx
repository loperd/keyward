import "./declared.css";
import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Alert, Icon, Modal, Skeleton } from "../ui";
import { t, tError } from "../i18n";
import type { PluginScreenProps } from "../plugins/types";
import { act, view } from "./channel";
import { foldContext } from "./layout";
import { Ctx, Nodes, PageHead, type Run } from "./Render";
import { tx } from "./text";
import type { Action, Page } from "./types";

/// Where a plugin's declared section is: its route, and the drawer and the
/// dialogue over it. Kept per plugin, outside the tree, so a section left and
/// come back to opens where it was.
type Where = { route: string; drawer: Page | null; dialog: Page | null; epoch: number; toast: string | null };

const stores = new Map<string, { get: () => Where; set: (w: Where) => void; sub: (l: () => void) => () => void }>();

function storeOf(plugin: string) {
  let s = stores.get(plugin);
  if (!s) {
    let value: Where = { route: "", drawer: null, dialog: null, epoch: 0, toast: null };
    const listeners = new Set<() => void>();
    s = {
      get: () => value,
      set: (w) => {
        value = w;
        for (const l of listeners) l();
      },
      sub: (l) => {
        listeners.add(l);
        return () => listeners.delete(l);
      },
    };
    stores.set(plugin, s);
  }
  return s;
}

function useWhere(plugin: string): [Where, (w: Partial<Where>) => void] {
  const s = storeOf(plugin);
  const w = useSyncExternalStore(s.sub, s.get);
  return [w, (patch) => s.set({ ...s.get(), ...patch })];
}

/// Carries out an action and does what its reply says.
function useRun(plugin: string): Run {
  const [, set] = useWhere(plugin);
  return useCallback(
    async (action: Action, form?: Record<string, string>) => {
      const s = storeOf(plugin);
      try {
        const r = await act(plugin, action.op, action.payload, form);
        const now = s.get();
        const patch: Partial<Where> = {};
        if (r.go !== undefined) Object.assign(patch, { route: r.go, drawer: null });
        if (r.drawer) patch.drawer = r.drawer;
        if (r.close_drawer) patch.drawer = null;
        if (r.dialog) patch.dialog = r.dialog;
        if (r.close_dialog) patch.dialog = null;
        if (r.toast) patch.toast = tx(r.toast);
        if (r.refresh) patch.epoch = now.epoch + 1;
        if (Object.keys(patch).length) set(patch);
        return r;
      } catch (e) {
        set({ toast: tError(String(e)) });
        return null;
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [plugin],
  );
}

/// A page the plugin gives for a route, asked again when it says so.
function usePage(plugin: string, route: string, epoch: number) {
  const [page, setPage] = useState<Page | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let every: number | undefined;
    // A screen that asks to be asked again goes on being asked through a
    // failed answer: the last page stays, the error is said over it.
    const load = () =>
      view(plugin, route)
        .then((p) => {
          if (!alive) return;
          setPage(p);
          setError(null);
          every = p.refresh_ms;
        })
        .catch((e) => alive && setError(String(e)))
        .finally(() => {
          if (alive && every) timer = setTimeout(load, Math.max(500, every));
        });
    void load();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [plugin, route, epoch]);
  return { page, error };
}

/// The drawer: on the right, the whole height; while it is open the
/// section's column steps aside through the window's layout.
function Drawer({ page, onClose }: { page: Page; onClose: () => void }) {
  useEffect(() => foldContext(), []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && !e.defaultPrevented && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <aside className="dv-drawer" role="dialog" aria-label={tx(page.title)}>
      <PageHead
        page={page}
        trailing={
          <button type="button" className="btn icon-only" title={t("dv.close")} aria-label={t("dv.close")} onClick={onClose}>
            <Icon name="close" size={14} />
          </button>
        }
      />
      <div className="dv-drawer-body">
        <Nodes nodes={page.body} />
      </div>
    </aside>
  );
}

/// A plugin's declared section: the screen for its route, with the drawer
/// and the dialogue over it.
export function DeclaredScreen({ manifest }: PluginScreenProps) {
  const plugin = manifest.id;
  const [where, set] = useWhere(plugin);
  const run = useRun(plugin);
  const { page, error } = usePage(plugin, where.route, where.epoch);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (!where.toast) return;
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => set({ toast: null }), 4000);
  }, [where.toast]);

  return (
    <Ctx.Provider value={{ plugin, run, epoch: where.epoch, go: (route: string) => set({ route, drawer: null }) }}>
      <div className={`dv-screen ${where.drawer ? "with-drawer" : ""}`}>
        {error && <Alert message={error} onRetry={() => set({ epoch: where.epoch + 1 })} />}
        {error && !page ? null : !page ? (
          <Skeleton rows={5} />
        ) : (
          <>
            <PageHead page={page} />
            <Nodes nodes={page.body} />
          </>
        )}
      </div>
      {where.drawer && <Drawer page={where.drawer} onClose={() => set({ drawer: null })} />}
      {where.dialog && (
        <Modal title={tx(where.dialog.title)} onClose={() => set({ dialog: null })} wide>
          <div className="dv-dialog">
            <Nodes nodes={where.dialog.body} />
          </div>
        </Modal>
      )}
      {where.toast && (
        <div className="dv-toast" role="status">
          {where.toast}
        </div>
      )}
    </Ctx.Provider>
  );
}
