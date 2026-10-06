// I-A Dense Ledger — the default Inventory presentation
// (vault-desk-i-a-dense-ledger-spatial-spec.md). One dominant ledger plane, a
// compact local chrome of two rows at most, a selection strip only while
// something is selected, Q-A inline beneath its row. Focus is not selection.
import { useEffect, useLayoutEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon, Picker } from "../ui";
import { currentLang, t, tError } from "../i18n";
import type { Catalog, VaultItem } from "../types";
import { KIND_ICON, KIND_KEY, LEVEL_MARK, LEVEL_RANK, ago, context, relationCount, shared, signals, topSignal, type Level } from "./model";

/// The set the ledger shows: everything, the favourites, the trash, a folder,
/// an organisation.
export type InventorySet = { kind: "all" } | { kind: "favorites" } | { kind: "trash" } | { kind: "folder"; id: string | null } | { kind: "org"; id: string };
type Sort = "security" | "name" | "updated";

/// What the Inventory session keeps across navigation: its semantic state
/// and, at departure, where focus, selection and scroll were (§8).
export type InventoryState = {
  set: InventorySet;
  query: string;
  kind: "all" | VaultItem["kind"];
  level: "all" | Level;
  sort: Sort;
  focused: string | null;
  selected: string[];
  anchor: string | null;
  scrollTop: number;
};
export const INVENTORY_START: InventoryState = { set: { kind: "all" }, query: "", kind: "all", level: "all", sort: "security", focused: null, selected: [], anchor: null, scrollTop: 0 };

function inSet(item: VaultItem, set: InventorySet): boolean {
  if (set.kind === "trash") return item.deleted;
  if (item.deleted) return false;
  if (set.kind === "favorites") return item.favorite;
  if (set.kind === "folder") return item.folder_id === set.id;
  if (set.kind === "org") return item.org_id === set.id;
  return true;
}

export function Inventory({
  catalog,
  loading,
  state,
  onState,
  onOpen,
  onRelations,
  onCreate,
  onTrash,
  onCopied,
}: {
  catalog: Catalog | null;
  loading: boolean;
  state: InventoryState;
  onState: (patch: Partial<InventoryState>) => void;
  onOpen: (id: string, pinned: boolean) => void;
  onRelations: (id: string) => void;
  onCreate: () => void;
  onTrash: (ids: string[]) => void;
  onCopied: (text: string) => void;
}) {
  const all = catalog?.items ?? [];
  const [peek, setPeek] = useState<string | null>(null);
  const body = useRef<HTMLDivElement>(null);
  const lang = currentLang();

  const counts = useMemo(() => new Map(all.map((i) => [i.id, relationCount(i, all)])), [all]);
  const rows = useMemo(() => {
    const q = state.query.trim().toLowerCase();
    const list = all.filter((item) => {
      if (!inSet(item, state.set)) return false;
      if (state.kind !== "all" && item.kind !== state.kind) return false;
      if (state.level !== "all" && topSignal(item).level !== state.level) return false;
      if (!q) return true;
      return [item.name, item.subtitle, item.folder_name, item.org_name, ...item.uris, ...Object.values(item.tags)].filter(Boolean).join(" ").toLowerCase().includes(q);
    });
    const byName = (a: VaultItem, b: VaultItem) => a.name.localeCompare(b.name, lang);
    if (state.sort === "name") return list.sort(byName);
    if (state.sort === "updated") return list.sort((a, b) => (b.revised ?? "").localeCompare(a.revised ?? "") || byName(a, b));
    return list.sort((a, b) => LEVEL_RANK[topSignal(a).level] - LEVEL_RANK[topSignal(b).level] || byName(a, b));
  }, [all, state.set, state.kind, state.level, state.query, state.sort, lang]);


  const selected = useMemo(() => new Set(state.selected), [state.selected]);
  const focusIndex = rows.findIndex((r) => r.id === state.focused);

  // Focus always lands on a row that exists; a vanished one gives way to its
  // nearest neighbour rather than to the top.
  useEffect(() => {
    if (rows.length && focusIndex < 0) onState({ focused: rows[0].id });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows]);

  // The scroll is put back where it was when one comes back to the ledger.
  useLayoutEffect(() => {
    if (body.current) body.current.scrollTop = state.scrollTop;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /// Q-A retargeting keeps the focused row where the eye is (§7.4).
  const moveFocus = (to: number, extend: boolean) => {
    const target = rows[Math.max(0, Math.min(rows.length - 1, to))];
    if (!target) return;
    const before = body.current?.querySelector<HTMLElement>(`[data-row="${state.focused}"]`)?.getBoundingClientRect().top;
    const patch: Partial<InventoryState> = { focused: target.id };
    if (extend) {
      const anchor = state.anchor ?? state.focused ?? target.id;
      const a = rows.findIndex((r) => r.id === anchor);
      const b = rows.findIndex((r) => r.id === target.id);
      patch.selected = rows.slice(Math.min(a, b), Math.max(a, b) + 1).map((r) => r.id);
      patch.anchor = anchor;
    }
    onState(patch);
    if (peek) setPeek(target.id);
    requestAnimationFrame(() => {
      const row = body.current?.querySelector<HTMLElement>(`[data-row="${target.id}"]`);
      if (!row || !body.current) return;
      if (peek && before !== undefined) body.current.scrollTop += row.getBoundingClientRect().top - before;
      else row.scrollIntoView({ block: "nearest" });
    });
  };

  useEffect(() => {
    const keys = (e: KeyboardEvent) => {
      const typing = (e.target as HTMLElement | null)?.matches?.("input, textarea, [contenteditable]");
      if (typing) return;
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        moveFocus(focusIndex + (e.key === "ArrowDown" ? 1 : -1), e.shiftKey);
      } else if (e.key === " " && state.focused) {
        e.preventDefault();
        setPeek((p) => (p === state.focused ? null : state.focused));
      } else if (e.key === "Enter" && state.focused) {
        e.preventDefault();
        setPeek(null);
        onOpen(state.focused, e.metaKey || e.ctrlKey);
      } else if ((e.key === "r" || e.key === "R") && !e.metaKey && !e.ctrlKey && state.focused) {
        e.preventDefault();
        setPeek(null);
        onRelations(state.focused);
      } else if (e.key === "Escape") {
        if (peek) setPeek(null);
        else if (state.selected.length) onState({ selected: [], anchor: null });
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "a") {
        e.preventDefault();
        onState({ selected: rows.map((r) => r.id) });
      }
    };
    window.addEventListener("keydown", keys);
    return () => window.removeEventListener("keydown", keys);
  });

  /// §6.2: a click on the body focuses and clears the selection; the gutter
  /// and Cmd toggle; Shift selects a range from the anchor.
  const click = (e: ReactMouseEvent, id: string, gutter: boolean) => {
    if (e.shiftKey) {
      const anchor = state.anchor ?? state.focused ?? id;
      const a = rows.findIndex((r) => r.id === anchor);
      const b = rows.findIndex((r) => r.id === id);
      onState({ focused: id, anchor, selected: rows.slice(Math.min(a, b), Math.max(a, b) + 1).map((r) => r.id) });
    } else if (gutter || e.metaKey || e.ctrlKey) {
      const next = new Set(selected);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      onState({ focused: id, anchor: id, selected: [...next] });
    } else {
      onState({ focused: id, anchor: id, selected: [] });
    }
  };

  const setLabel = (() => {
    const s = state.set;
    if (s.kind === "favorites") return t("items.favorites");
    if (s.kind === "trash") return t("items.trash");
    if (s.kind === "folder") return s.id === null ? t("items.unfiled") : (catalog?.folders.find((f) => f.id === s.id)?.name ?? "—");
    if (s.kind === "org") return catalog?.orgs.find((o) => o.id === s.id)?.name ?? "—";
    return t("desk.set.all");
  })();
  const setKey = (s: InventorySet) => (s.kind === "folder" ? `folder:${s.id ?? ""}` : s.kind === "org" ? `org:${s.id}` : s.kind);
  const setOptions = [
    { id: "all", label: t("desk.set.all") },
    { id: "favorites", label: t("items.favorites") },
    ...(catalog?.folders ?? []).map((f) => ({ id: `folder:${f.id}`, label: f.name, hint: String(f.count) })),
    ...(catalog?.orgs ?? []).map((o) => ({ id: `org:${o.id}`, label: o.name })),
    { id: "trash", label: t("items.trash"), hint: String(catalog?.trash ?? 0) },
  ];
  const pickSet = (id: string) => {
    const set: InventorySet = id.startsWith("folder:") ? { kind: "folder", id: id.slice(7) || null } : id.startsWith("org:") ? { kind: "org", id: id.slice(4) } : ({ kind: id } as InventorySet);
    onState({ set, selected: [], anchor: null });
  };

  const copy = async (id: string, field: "username" | "password" | "totp") => {
    try {
      await invoke("copy_secret", { entryId: id, field });
      onCopied(t("desk.copied", { what: t(`desk.field.${field}` as "desk.field.username") }));
    } catch (e) {
      onCopied(tError(String(e)));
    }
  };

  return (
    <main className="desk-mode inventory">
      <header className="ledger-chrome">
        <div className="ledger-chrome-row">
          <span className="ledger-set">
            <Picker value={setKey(state.set)} options={setOptions} placeholder={setLabel} onChange={pickSet} />
            <span className="ledger-count">{rows.length.toLocaleString(lang)}</span>
          </span>
          <span className="grow" />
          <button type="button" className="btn primary" onClick={onCreate}>
            <Icon name="plus" size={14} />
            {t("desk.new")}
          </button>
        </div>
        <div className="ledger-chrome-row">
          <label className="ledger-query">
            <Icon name="search" size={14} />
            <input value={state.query} onChange={(e) => onState({ query: e.target.value })} placeholder={t("desk.query")} aria-label={t("desk.query")} spellCheck={false} />
          </label>
          <span className="ledger-control">
            <Picker
              value={state.kind}
              placeholder={t("desk.filter.kind")}
              options={[{ id: "all", label: t("desk.filter.anyKind") }, ...(Object.keys(KIND_KEY) as VaultItem["kind"][]).map((k) => ({ id: k, label: t(KIND_KEY[k]) }))]}
              onChange={(v) => onState({ kind: v as InventoryState["kind"] })}
            />
          </span>
          <span className="ledger-control">
            <Picker
              value={state.level}
              placeholder={t("desk.filter.security")}
              options={[{ id: "all", label: t("desk.filter.anySecurity") }, ...(["critical", "action", "warning", "healthy", "unknown"] as Level[]).map((l) => ({ id: l, label: t(`desk.level.${l}` as "desk.level.critical") }))]}
              onChange={(v) => onState({ level: v as InventoryState["level"] })}
            />
          </span>
          <span className="ledger-control">
            <Picker
              value={state.sort}
              placeholder={t("desk.sort")}
              options={(["security", "name", "updated"] as Sort[]).map((s) => ({ id: s, label: t(`desk.sortBy.${s}` as "desk.sortBy.security") }))}
              onChange={(v) => onState({ sort: v as Sort })}
            />
          </span>
        </div>
      </header>

      {state.selected.length > 0 && (
        <div className="ledger-selection" role="toolbar">
          <b>{t("desk.selected", { n: state.selected.length })}</b>
          {state.set.kind !== "trash" && (
            <button type="button" className="btn" onClick={() => onTrash(state.selected)}>
              <Icon name="trash" size={14} />
              {t("item.trash")}
            </button>
          )}
          {state.selected.length === 1 && (
            <button type="button" className="btn" onClick={() => onRelations(state.selected[0])}>
              <Icon name="network" size={14} />
              {t("desk.explore")}
            </button>
          )}
          <span className="grow" />
          <button type="button" className="btn" onClick={() => onState({ selected: [], anchor: null })}>
            {t("desk.clear")}
          </button>
        </div>
      )}

      <div className="ledger" role="grid" aria-rowcount={rows.length} ref={body} onScroll={(e) => onState({ scrollTop: e.currentTarget.scrollTop })}>
        <div className="ledger-head" role="row">
          <span className="ledger-gutter" />
          <span>{t("desk.col.type")}</span>
          <span>{t("desk.col.label")}</span>
          <span>{t("desk.col.context")}</span>
          <span>{t("desk.col.owner")}</span>
          <span>{t("desk.col.security")}</span>
          <span>{t("desk.col.updated")}</span>
          <span className="right">{t("desk.col.relations")}</span>
        </div>
        {loading && rows.length === 0 &&
          Array.from({ length: 8 }, (_, i) => (
            <div className="ledger-row placeholder" key={i} aria-hidden="true">
              <span />
            </div>
          ))}
        {!loading && rows.length === 0 && (
          <div className="ledger-empty">
            <span>{t("desk.empty")}</span>
            {(state.query || state.kind !== "all" || state.level !== "all") && (
              <button type="button" className="btn" onClick={() => onState({ query: "", kind: "all", level: "all" })}>
                {t("desk.clearQuery")}
              </button>
            )}
          </div>
        )}
        {rows.map((item) => {
          const sig = topSignal(item);
          const focused = item.id === state.focused;
          const isSelected = selected.has(item.id);
          return (
            <div key={item.id} className="ledger-entry" style={{ viewTransitionName: `row-${item.id}` }}>
              <div
                className={`ledger-row ${focused ? "focused" : ""} ${isSelected ? "selected" : ""}`}
                role="row"
                aria-selected={isSelected}
                data-row={item.id}
                onClick={(e) => click(e, item.id, false)}
                onDoubleClick={(e) => onOpen(item.id, e.metaKey || e.ctrlKey)}
              >
                <span
                  className="ledger-gutter"
                  role="checkbox"
                  aria-checked={isSelected}
                  aria-label={item.name}
                  onClick={(e) => {
                    e.stopPropagation();
                    click(e, item.id, true);
                  }}
                >
                  {isSelected && <Icon name="check" size={12} />}
                </span>
                <span className="ledger-type" title={t(KIND_KEY[item.kind])}>
                  <Icon name={KIND_ICON[item.kind]} size={16} />
                </span>
                <span className="ledger-label">
                  <b>{item.name}</b>
                  {item.subtitle && <small>{item.subtitle}</small>}
                </span>
                <span className="ledger-context">{context(item) ?? <i>{t("desk.noContext")}</i>}</span>
                <span className="ledger-owner">{shared(item) ? t("desk.owner.shared") : t("desk.owner.personal")}</span>
                <span className={`ledger-security ${sig.level}`} title={signals(item).map((s) => t(s.key, s.args)).join(" · ")}>
                  <i aria-hidden="true">{LEVEL_MARK[sig.level]}</i>
                  {t(sig.key, sig.args)}
                </span>
                <span className="ledger-time">{ago(item.revised, lang)}</span>
                <button
                  type="button"
                  className="ledger-relations"
                  title={t("desk.explore")}
                  onClick={(e) => {
                    e.stopPropagation();
                    onRelations(item.id);
                  }}
                >
                  <Icon name="link" size={12} />
                  {counts.get(item.id) ?? 0}
                </button>
              </div>
              {peek === item.id && (
                <InlinePeek
                  item={item}
                  relations={counts.get(item.id) ?? 0}
                  onCopy={(f) => void copy(item.id, f)}
                  onOpen={() => {
                    setPeek(null);
                    onOpen(item.id, false);
                  }}
                  onRelations={() => {
                    setPeek(null);
                    onRelations(item.id);
                  }}
                  onDismiss={() => setPeek(null)}
                />
              )}
            </div>
          );
        })}
      </div>
    </main>
  );
}

/// Q-A: decision-making and immediate use, never an automatic reveal (§7.2).
function InlinePeek({
  item,
  relations,
  onCopy,
  onOpen,
  onRelations,
  onDismiss,
}: {
  item: VaultItem;
  relations: number;
  onCopy: (field: "username" | "password" | "totp") => void;
  onOpen: () => void;
  onRelations: () => void;
  onDismiss: () => void;
}) {
  const all = signals(item);
  return (
    <div className="ledger-peek" role="region" aria-label={item.name}>
      <div className="ledger-peek-facts">
        <span>{[t(KIND_KEY[item.kind]), context(item), shared(item) ? t("desk.owner.shared") : t("desk.owner.personal")].filter(Boolean).join(" · ")}</span>
        <span className="ledger-peek-signals">
          {all.map((s) => (
            <span key={s.key} className={`ledger-security ${s.level}`}>
              <i aria-hidden="true">{LEVEL_MARK[s.level]}</i>
              {t(s.key, s.args)}
            </span>
          ))}
          <span className="ledger-peek-rel">
            <Icon name="link" size={12} />
            {t("desk.relationsN", { n: relations })}
          </span>
        </span>
      </div>
      <div className="ledger-peek-actions">
        {item.kind === "login" && (
          <>
            {item.subtitle && (
              <button type="button" className="btn" onClick={() => onCopy("username")}>
                <Icon name="copy" size={14} />
                {t("desk.field.username")}
              </button>
            )}
            <button type="button" className="btn" onClick={() => onCopy("password")}>
              <Icon name="copy" size={14} />
              {t("desk.field.password")}
            </button>
            {item.has_totp && (
              <button type="button" className="btn" onClick={() => onCopy("totp")}>
                <Icon name="copy" size={14} />
                {t("desk.field.totp")}
              </button>
            )}
          </>
        )}
        <span className="grow" />
        <button type="button" className="btn" onClick={onRelations}>
          <Icon name="network" size={14} />
          {t("desk.explore")}
          <kbd>R</kbd>
        </button>
        <button type="button" className="btn primary" onClick={onOpen}>
          {t("desk.open")}
          <kbd>↵</kbd>
        </button>
        <button type="button" className="btn icon-only" title={t("dv.close")} aria-label={t("dv.close")} onClick={onDismiss}>
          <Icon name="close" size={14} />
        </button>
      </div>
    </div>
  );
}
