// Vault Desk — the vault section (vault-desk-final-ux-spec.md). Inventory
// (I-A), the Object Workspace (O-B) and Relationship Exploration (R-B) under
// the window's one chrome; a strip of workspace tabs only while documents are
// open. Where in the desk the window is belongs to the window's history; the
// desk keeps its sessions (the ledger's state, the open documents) itself.
import "./desk/desk.css";
import { useEffect, useState } from "react";
import { Icon } from "./ui";
import { t } from "./i18n";
import type { Catalog } from "./types";
import { KIND_ICON } from "./desk/model";
import { INVENTORY_START, Inventory, type InventorySet, type InventoryState } from "./desk/Inventory";
import { ObjectPage } from "./desk/ObjectPage";
import { Relations } from "./desk/Relations";

type DeskMode = "inventory" | "object" | "relations";
/// Where in the vault the window is: the ledger, an object, its relations.
export type DeskLocation = { mode: DeskMode; objectId?: string; relationRoot?: string };
/// `passive`: a tab switched to, which is no step of the history (§6.8).
export type DeskNavigate = (to: DeskLocation, opts?: { passive?: boolean }) => void;

// The sessions outlive the desk's unmounting — another section opened and
// left — as the spec's checkpoints outlive a departure.
let inventoryKept: InventoryState = INVENTORY_START;
let documentsKept: { id: string; pinned: boolean }[] = [];

export function VaultDesk({
  catalog,
  loading,
  location,
  onNavigate,
  onCreate,
  onChanged,
  onNotice,
  onTrash,
  onRestore,
  onPurge,
}: {
  catalog: Catalog | null;
  loading: boolean;
  location: DeskLocation;
  onNavigate: DeskNavigate;
  onCreate: () => void;
  onChanged: () => void;
  onNotice: (text: string) => void;
  onTrash: (ids: string[]) => void;
  onRestore: (id: string) => void;
  onPurge: (id: string) => void;
}) {
  const [inventory, setInventory] = useState<InventoryState>(inventoryKept);
  const [documents, setDocuments] = useState(documentsKept);
  useEffect(() => {
    inventoryKept = inventory;
  }, [inventory]);
  useEffect(() => {
    documentsKept = documents;
  }, [documents]);

  const all = catalog?.items ?? [];
  const objectId = location.mode === "object" ? location.objectId ?? null : null;

  /// Opening an object makes it a document: a plain one is replaced by the
  /// next plain one, a pinned one stays (⌘Enter / ⌘double-click).
  const open = (id: string, pinned = false) => {
    setDocuments((docs) => {
      const has = docs.find((d) => d.id === id);
      if (has) return pinned ? docs.map((d) => (d.id === id ? { ...d, pinned: true } : d)) : docs;
      return [...docs.filter((d) => d.pinned), { id, pinned }];
    });
    onNavigate({ mode: "object", objectId: id });
  };
  const close = (id: string) => {
    const rest = documents.filter((d) => d.id !== id);
    setDocuments(rest);
    if (objectId === id) {
      const next = rest.at(-1);
      onNavigate(next ? { mode: "object", objectId: next.id } : { mode: "inventory" }, { passive: true });
    }
  };

  // ⌘W closes the active document; ⌘1…9 switch tabs without a history step.
  useEffect(() => {
    const keys = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey)) return;
      if (e.key.toLowerCase() === "w" && objectId) {
        e.preventDefault();
        close(objectId);
      } else if (/^[1-9]$/.test(e.key) && documents[Number(e.key) - 1]) {
        e.preventDefault();
        onNavigate({ mode: "object", objectId: documents[Number(e.key) - 1].id }, { passive: true });
      }
    };
    window.addEventListener("keydown", keys);
    return () => window.removeEventListener("keydown", keys);
  });

  return (
    <section className="vault-desk">
      {documents.length > 0 && (
        <nav className="desk-tabs" aria-label={t("desk.documents")}>
          {location.mode !== "object" && (
            <button type="button" className="desk-tab back" onClick={() => onNavigate({ mode: "inventory" }, { passive: true })} aria-current={location.mode === "inventory"}>
              <Icon name="all" size={14} />
              {t("desk.set.all")}
            </button>
          )}
          {documents.map((d, i) => {
            const it = all.find((x) => x.id === d.id);
            if (!it) return null;
            return (
              <button
                type="button"
                key={d.id}
                className={`desk-tab ${objectId === d.id ? "on" : ""} ${d.pinned ? "pinned" : ""}`}
                title={`${it.name} (⌘${i + 1})`}
                onClick={() => onNavigate({ mode: "object", objectId: d.id }, { passive: true })}
              >
                <Icon name={KIND_ICON[it.kind]} size={14} />
                <span>{it.name}</span>
                <span
                  className="desk-tab-close"
                  role="button"
                  aria-label={t("dv.close")}
                  onClick={(e) => {
                    e.stopPropagation();
                    close(d.id);
                  }}
                >
                  <Icon name="close" size={12} />
                </span>
              </button>
            );
          })}
        </nav>
      )}
      {location.mode === "inventory" && (
        <Inventory
          catalog={catalog}
          loading={loading}
          state={inventory}
          onState={(patch) => setInventory((s) => ({ ...s, ...patch }))}
          onOpen={open}
          onRelations={(id) => onNavigate({ mode: "relations", relationRoot: id })}
          onCreate={onCreate}
          onTrash={onTrash}
          onCopied={onNotice}
        />
      )}
      {location.mode === "object" && objectId && (
        <ObjectPage
          key={objectId}
          id={objectId}
          item={all.find((i) => i.id === objectId) ?? null}
          all={all}
          onRelations={(id) => onNavigate({ mode: "relations", relationRoot: id })}
          onOpen={(id) => open(id)}
          onChanged={onChanged}
          onNotice={onNotice}
          onTrash={(id) => {
            close(id);
            onTrash([id]);
          }}
          onRestore={onRestore}
          onPurge={(id) => {
            close(id);
            onPurge(id);
          }}
        />
      )}
      {location.mode === "relations" && location.relationRoot && (
        <Relations
          rootId={location.relationRoot}
          all={all}
          onOpen={(id) => open(id)}
          onInventory={(set: InventorySet) => {
            setInventory((s) => ({ ...s, set, selected: [], anchor: null }));
            onNavigate({ mode: "inventory" });
          }}
        />
      )}
    </section>
  );
}
