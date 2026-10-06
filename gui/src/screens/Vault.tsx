import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useImageHue, useSiteIcon } from "../icons";
import { folderColor } from "../folders";
import { Countdown, prettyCode, useTotpCode } from "../Totp";
import { Alert, Empty, Icon, ScreenHead, Skeleton } from "../ui";
import type { LocalChange } from "./Detail";
import { CardBrandMark, detectCardBrand } from "../CardBrand";
import { t } from "../i18n";
import { kindKey, type Catalog, type VaultItem } from "../types";

/// A slice of the list.
///
/// Three independent axes rather than one switch. A folder is a person's own
/// arrangement, an organisation is whose vault it is; in Bitwarden an item is
/// in a folder and in an organisation at the same time, so "Work" and "Acme"
/// must not switch each other off. They used to share one union — and choosing
/// a folder cleared the organisation.
export type Filter = {
  view: { kind: "all" } | { kind: "type"; value: string } | { kind: "favorites" } | { kind: "passkeys" } | { kind: "trash" };
  /// `undefined` is any of them, `null` is "no folder", a string is a
  /// particular one.
  folder?: string | null;
  /// `undefined` is any of them.
  org?: string;
};

/// Whether the slice shows the trash.
export function isTrash(filter: Filter): boolean {
  return filter.view.kind === "trash";
}

/// How many rows are shown at once and how many are added at a time. Sixty
/// cover any screen with room to spare, and after that the list grows as it is
/// scrolled — there is no point keeping four hundred nodes in the DOM.
const PAGE = 60;

/// The list of items, loaded lazily.
export function VaultScreen({
  catalog,
  filter,
  query,
  loading,
  selected,
  onSelect,
  serverUrl,
  onCopied,
  onChanged,
  onLocal,
}: {
  catalog: Catalog | null;
  filter: Filter;
  query: string;
  loading: boolean;
  selected: string | null;
  onSelect: (id: string) => void;
  serverUrl: string;
  onCopied: (text: string) => void;
  onChanged: () => void;
  /// A change shown before the server confirms it (see the card's).
  onLocal: (change: LocalChange) => { undo: () => void; settle: () => void };
}) {
  // Picking works only in the trash: that is where it is needed — things are
  // deleted from there in batches, and one item at a time is a dozen
  // presses.
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => setPicked(new Set()), [filter.view.kind]);

  const items = useMemo(() => {
    if (!catalog) return [];
    const q = query.trim().toLowerCase();
    return catalog.items.filter((i) => {
      // The trash lives apart: a deleted item must not turn up in the
      // ordinary list, or it will be copied and its absence will make no
      // sense.
      if (isTrash(filter)) {
        if (!i.deleted) return false;
      } else if (i.deleted) {
        return false;
      }
      if (filter.view.kind === "favorites" && !i.favorite) return false;
      if (filter.view.kind === "passkeys" && i.passkeys === 0) return false;
      if (filter.view.kind === "type" && kindKey(i.kind) !== filter.view.value) return false;
      // The axes add up: a folder and an organisation narrow the list
      // together rather than instead of each other.
      if (filter.folder !== undefined && (i.folder_id ?? null) !== filter.folder) return false;
      if (filter.org !== undefined && i.org_id !== filter.org) return false;
      if (!q) return true;
      return (
        i.name.toLowerCase().includes(q) ||
        (i.subtitle ?? "").toLowerCase().includes(q) ||
        Object.values(i.tags).some((v) => v.toLowerCase().includes(q)) ||
        i.uris.some((u) => u.toLowerCase().includes(q))
      );
    });
  }, [catalog, filter, query]);

  const [limit, setLimit] = useState(PAGE);
  const sentinel = useRef<HTMLDivElement | null>(null);

  // A change of filter or of query is a new list, and it has to be shown from
  // the top rather than from the depth the previous one was scrolled to.
  useEffect(() => {
    setLimit(PAGE);
  }, [filter, query]);

  useEffect(() => {
    const node = sentinel.current;
    if (!node) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) setLimit((n) => n + PAGE);
      },
      // Loaded in advance, so that the bottom of the list does not run into
      // emptiness.
      { rootMargin: "300px" },
    );
    io.observe(node);
    return () => io.disconnect();
  }, [items.length, limit]);

  // As on the card: the trash empties at once, the server confirms after.
  // `[]` is the whole trash.
  const purge = async (ids: string[]) => {
    const targets = ids.length ? ids : (catalog?.items ?? []).filter((i) => i.deleted).map((i) => i.id);
    const locals = targets.map((id) => onLocal({ kind: "purged", id }));
    setPicked(new Set());
    setBusy(true);
    setError(null);
    try {
      await invoke("purge_items", { entryIds: ids });
    } catch (e) {
      // The first change's "before" is the list as it was: undone last.
      [...locals].reverse().forEach((l) => l.undo());
      setError(String(e));
    } finally {
      locals.forEach((l) => l.settle());
      setBusy(false);
      onChanged();
    }
  };

  if (loading && !catalog) return <Skeleton rows={7} />;

  const shown = items.slice(0, limit);
  if (items.length === 0)
    return isTrash(filter) ? (
      <Empty icon="warn" title={t("trash.none")} body={t("trash.noneHint")} />
    ) : (
      <Empty icon="search" title={t("items.empty")} body={t("items.emptyHint")} />
    );

  return (
    <div className="scroller">
      {isTrash(filter) && items.length > 0 && (
        <div className="bulk">
          <label className="pickall">
            <input
              type="checkbox"
              checked={picked.size === items.length}
              onChange={(e) => setPicked(e.target.checked ? new Set(items.map((i) => i.id)) : new Set())}
            />
            <span>{picked.size > 0 ? t("trash.picked", { n: picked.size }) : t("trash.pickAll")}</span>
          </label>
          {/* Picking and deleting what is picked is one thing, on the left;
              emptying the whole trash is another, a button of its own on the
              right. Two red buttons side by side read as one action. */}
          {picked.size > 0 && (
            <button type="button" className="btn danger" disabled={busy} onClick={() => void purge([...picked])}>
              {t("trash.purgePicked", { n: picked.size })}
            </button>
          )}
          <span className="grow" />
          <button type="button" className="btn empty-trash" disabled={busy} onClick={() => void purge([])}>
            <Icon name="trash" size={13} />
            {t("trash.empty")}
          </button>
        </div>
      )}

      {error && <Alert message={error} />}

      <ScreenHead icon="all" title={t("nav.items")} count={items.length} />

      <div className="list vault-list">
        {shown.map((i) =>
          isTrash(filter) ? (
            <div className="picked-row" key={i.id}>
              <input
                type="checkbox"
                checked={picked.has(i.id)}
                aria-label={i.name}
                onChange={(e) =>
                  setPicked((cur) => {
                    const next = new Set(cur);
                    if (e.target.checked) next.add(i.id);
                    else next.delete(i.id);
                    return next;
                  })
                }
              />
              <ItemRow
                item={i}
                active={i.id === selected}
                onSelect={() => onSelect(i.id)}
                serverUrl={serverUrl}
                onCopied={onCopied}
                showFolder={false}
              />
            </div>
          ) : (
          <ItemRow
            key={i.id}
            item={i}
            active={i.id === selected}
            onSelect={() => onSelect(i.id)}
            serverUrl={serverUrl}
            onCopied={onCopied}
            showFolder={filter.folder === undefined}
          />
          ),
        )}
      </div>
      {limit < items.length && (
        <div className="more" ref={sentinel}>
          <Skeleton rows={2} />
        </div>
      )}
    </div>
  );
}

function RowTotp({ id, onCopied }: { id: string; onCopied: (t: string) => void }) {
  const [hover, setHover] = useState(false);
  const { code, left } = useTotpCode(id, hover);

  return (
    <span
      className={`totp-chip ${code ? "live" : ""}`}
      role="button"
      tabIndex={0}
      title="TOTP"
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      onFocus={() => setHover(true)}
      onBlur={() => setHover(false)}
      onClick={(e) => {
        e.stopPropagation();
        void invoke<number>("copy_secret", { entryId: id, field: "totp" })
          .then(() => onCopied(t("detail.copied", { sec: 30 })))
          .catch((err) => onCopied(String(err)));
      }}
    >
      {code ? (
        <>
          <span className="mono swap" key={code}>
            {prettyCode(code)}
          </span>
          <Countdown left={left} />
        </>
      ) : (
        <Icon name="clock" size={13} />
      )}
    </span>
  );
}

function ItemRow({
  item,
  active,
  onSelect,
  serverUrl,
  onCopied,
  showFolder,
}: {
  item: VaultItem;
  active: boolean;
  onSelect: () => void;
  serverUrl: string;
  onCopied: (text: string) => void;
  showFolder: boolean;
}) {
  const favicon = useSiteIcon(serverUrl, item.uris, item.kind === "login") ?? null;
  const broken = false;
  const cardBrand = item.kind === "card" ? detectCardBrand(null, item.card_brand) : null;
  const iconHue = useImageHue(favicon);
  // A selected row needs one stable interaction colour. Name-derived hues
  // made selection jump from lime to magenta as a person moved through the
  // list, which reads as arbitrary rather than intentional.
  const hue = favicon ? iconHue : null;
  const kindIcon = item.kind === "secure_note" ? "note" : item.kind;

  return (
    <button type="button"
      className={`row item ${active ? "active" : ""}${hue === null ? "" : " hued"}`}
      // A name for the view transition: the row folds away when it leaves the
      // list and the rest slide up into its place.
      style={{ viewTransitionName: `row-${item.id}`, ...(hue === null ? {} : { ["--h" as string]: String(hue) }) } as React.CSSProperties}
      onClick={onSelect}
      title={item.folder_name ?? undefined}
    >
      <span className={`glyph kind-${item.kind}`}>
        {cardBrand ? (
          <CardBrandMark brand={cardBrand} />
        ) : favicon && !broken ? (
          // A site's icon is sometimes out of reach — we fall back to the
          // kind's glyph without a word rather than leaving a hole in the
          // list.
          <img src={favicon} alt="" loading="lazy" />
        ) : (
          <Icon name={kindIcon} size={17} />
        )}
      </span>
      <span className="text">
        <b>{item.name}</b>
        <span>{item.subtitle ?? item.folder_name ?? ""}</span>
      </span>
      <span className="side">
        {item.passkeys > 0 && (
          <span className="chip pk-badge" title={t("passkey.title", { n: item.passkeys })}>
            <Icon name="key" size={11} />
            {item.passkeys > 1 ? item.passkeys : ""}
          </span>
        )}
        {/* An item's own fields as chips: a route, a vault's address. The
            list does not know what they mean — a person wrote them, and they
            are what the item is recognised by. */}
        {Object.entries(item.tags).map(([name, value]) =>
          value.trim() ? (
            <span className="chip on" key={name} title={name}>
              {value}
            </span>
          ) : null,
        )}
        {item.has_totp && <RowTotp id={item.id} onCopied={onCopied} />}
        {/* A folder is a dot of its colour, as in the row of filters. This
            used to be a stripe the full height of the row on the left, and on
            the chosen row two colours ended up side by side: the blue
            highlight of the choice and, say, the lilac of the folder. One
            meaning, one way of showing it. */}
        {showFolder && item.folder_name && (
          <span
            className="dot"
            aria-hidden="true"
            style={{ background: folderColor(item.folder_name) }}
          />
        )}
      </span>
    </button>
  );
}
