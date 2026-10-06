// R-B Typed Adjacency — Relationship Exploration
// (vault-desk-final-ux-spec.md §4): one root, incoming and outgoing typed
// relations side by side, a selection tray while something is selected.
// Pivoting moves the root inside the session; it is not a global entry.
import { useEffect, useMemo, useState } from "react";
import { Icon, Picker } from "../ui";
import { t } from "../i18n";
import type { VaultItem } from "../types";
import { EDGE_KEY, KIND_ICON, KIND_KEY, LEVEL_MARK, context, relations, shared, topSignal, type Edge, type Relation } from "./model";
import type { InventorySet } from "./Inventory";

const NODE_ICON = { folder: "folder", org: "shield", domain: "globe", host: "server" } as const;

export function Relations({
  rootId,
  all,
  onOpen,
  onInventory,
}: {
  rootId: string;
  all: VaultItem[];
  onOpen: (id: string) => void;
  onInventory: (set: InventorySet) => void;
}) {
  // The session's own root: pivoting is a local revision (§4.5).
  const [root, setRoot] = useState(rootId);
  useEffect(() => setRoot(rootId), [rootId]);
  const [direction, setDirection] = useState<"both" | "incoming" | "outgoing">("both");
  const [edge, setEdge] = useState<"all" | Edge>("all");
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const item = all.find((i) => i.id === root) ?? null;
  const rels = useMemo(() => (item ? relations(item, all) : []), [item, all]);
  if (!item) return <main className="desk-mode relations"><p className="relations-none">{t("desk.rel.gone")}</p></main>;

  const shown = rels.filter((r) => (edge === "all" || r.edge === edge) && (direction === "both" || r.direction === direction));
  const incoming = shown.filter((r) => r.direction === "incoming");
  const outgoing = shown.filter((r) => r.direction === "outgoing");
  const sig = topSignal(item);
  const edges = [...new Set(rels.map((r) => r.edge))];
  const toggle = (id: string) =>
    setChosen((c) => {
      const n = new Set(c);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  return (
    <main className="desk-mode relations">
      <header className="relations-head">
        <div className="object-head-row">
          <span className="object-type" title={t(KIND_KEY[item.kind])}>
            <Icon name={KIND_ICON[item.kind]} size={20} />
          </span>
          <div className="object-ident">
            <h1>{item.name}</h1>
            <p>
              {[t(KIND_KEY[item.kind]), context(item), shared(item) ? t("desk.owner.shared") : t("desk.owner.personal")].filter(Boolean).join(" · ")}
              <span className={`ledger-security ${sig.level}`}>
                <i aria-hidden="true">{LEVEL_MARK[sig.level]}</i>
                {t(sig.key, sig.args)}
              </span>
            </p>
          </div>
          <span className="grow" />
          <button type="button" className="btn" onClick={() => onOpen(item.id)}>
            {t("desk.open")}
          </button>
        </div>
        <div className="ledger-chrome-row">
          <span className="ledger-control">
            <Picker
              value={direction}
              placeholder={t("desk.rel.direction")}
              options={[
                { id: "both", label: t("desk.rel.both") },
                { id: "incoming", label: t("desk.rel.incoming"), hint: String(rels.filter((r) => r.direction === "incoming").length) },
                { id: "outgoing", label: t("desk.rel.outgoing"), hint: String(rels.filter((r) => r.direction === "outgoing").length) },
              ]}
              onChange={(v) => setDirection(v as typeof direction)}
            />
          </span>
          <span className="ledger-control">
            <Picker
              value={edge}
              placeholder={t("desk.rel.type")}
              options={[{ id: "all", label: t("desk.rel.anyType") }, ...edges.map((e) => ({ id: e, label: t(EDGE_KEY[e]), hint: String(rels.filter((r) => r.edge === e).length) }))]}
              onChange={(v) => setEdge(v as typeof edge)}
            />
          </span>
          {root !== rootId && (
            <button type="button" className="btn" onClick={() => setRoot(rootId)}>
              <Icon name="undo" size={14} />
              {t("desk.rel.backToRoot")}
            </button>
          )}
        </div>
      </header>

      <div className="relations-sides">
        <Side title={t("desk.rel.incoming")} list={incoming} chosen={chosen} onToggle={toggle} onOpen={onOpen} onPivot={setRoot} onInventory={onInventory} />
        <Side title={t("desk.rel.outgoing")} list={outgoing} chosen={chosen} onToggle={toggle} onOpen={onOpen} onPivot={setRoot} onInventory={onInventory} />
      </div>

      {chosen.size > 0 && (
        <div className="ledger-selection tray" role="toolbar">
          <b>{t("desk.selected", { n: chosen.size })}</b>
          <button type="button" className="btn" onClick={() => [...chosen].forEach((id) => onOpen(id))}>
            {t("desk.rel.openAll")}
          </button>
          <span className="grow" />
          <button type="button" className="btn" onClick={() => setChosen(new Set())}>
            {t("desk.clear")}
          </button>
        </div>
      )}
    </main>
  );
}

/// One direction, grouped by the type of relation, each group with its count.
function Side({ title, list, chosen, onToggle, onOpen, onPivot, onInventory }: { title: string; list: Relation[]; chosen: Set<string>; onToggle: (id: string) => void; onOpen: (id: string) => void; onPivot: (id: string) => void; onInventory: (set: InventorySet) => void }) {
  const groups = [...new Set(list.map((r) => r.edge))];
  return (
    <section className="relations-side">
      <h2>
        {title}
        <span className="screen-head-count">{list.length}</span>
      </h2>
      {list.length === 0 && <p className="relations-none">{t("desk.rel.none")}</p>}
      {groups.map((g) => {
        const rows = list.filter((r) => r.edge === g);
        return (
          <div className="relations-group" key={g}>
            <h3>
              {t(EDGE_KEY[g])}
              <span>{rows.length}</span>
            </h3>
            {rows.map((r) => {
              if (r.node.kind === "object") {
                const it = r.node.item;
                const s = topSignal(it);
                return (
                  <div className={`relations-row ${chosen.has(it.id) ? "selected" : ""}`} key={`${g}:${it.id}`} onDoubleClick={() => onOpen(it.id)}>
                    <span className="ledger-gutter" role="checkbox" aria-checked={chosen.has(it.id)} aria-label={it.name} onClick={() => onToggle(it.id)}>
                      {chosen.has(it.id) && <Icon name="check" size={12} />}
                    </span>
                    <Icon name={KIND_ICON[it.kind]} size={16} />
                    <span className="relations-label">
                      <b>{it.name}</b>
                      <small>{context(it) ?? (shared(it) ? t("desk.owner.shared") : t("desk.owner.personal"))}</small>
                    </span>
                    <span className={`ledger-security ${s.level}`}>
                      <i aria-hidden="true">{LEVEL_MARK[s.level]}</i>
                      {t(s.key, s.args)}
                    </span>
                    <button type="button" className="btn icon-only" title={t("desk.rel.pivot")} aria-label={t("desk.rel.pivot")} onClick={() => onPivot(it.id)}>
                      <Icon name="network" size={14} />
                    </button>
                    <button type="button" className="btn" onClick={() => onOpen(it.id)}>
                      {t("desk.open")}
                    </button>
                  </div>
                );
              }
              const node = r.node;
              const set: InventorySet | null = node.kind === "folder" ? { kind: "folder", id: node.id } : node.kind === "org" ? { kind: "org", id: node.id } : null;
              return (
                <div className="relations-row is-context" key={`${g}:${node.kind}:${node.id}`}>
                  <span className="ledger-gutter" />
                  <Icon name={NODE_ICON[node.kind]} size={16} />
                  <span className="relations-label">
                    <b className={node.kind === "domain" || node.kind === "host" ? "mono" : ""}>{node.label}</b>
                    <small>{t(`desk.node.${node.kind}` as "desk.node.folder")}</small>
                  </span>
                  <span />
                  <span />
                  {set && (
                    <button type="button" className="btn" onClick={() => onInventory(set)}>
                      {t("desk.rel.toInventory")}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        );
      })}
    </section>
  );
}
