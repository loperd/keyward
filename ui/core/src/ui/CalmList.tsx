// The calm list: the answer to a flat question. A filter with nothing chosen
// is shown as one wide list — what was found, why it stands where it does,
// where it lives — rather than as a column with an empty sheet beside it.
import { useEffect, useRef, useState } from "react";
import { t, text } from "../i18n";
import { type Column, type Filter, type Query, TokenKey, ColumnType } from "../path/query";
import { STATES } from "../path/query";
import { currentPlace } from "../path/places";
import { Icon } from "./Icons";
import { Glyph, Tile, nodeLead, useCore } from "./marks";
import { Level } from "../model/types";
import { type Directory, ResultGroup, NodeKind } from "../path/directory";
import type { PathStore } from "../path/store";
import { tokenPx } from "./tokens";
import { WINDOW_FROM, layoutOf, nearestScroll, offsetIn, spacersOf, useWindow, type RowLayout } from "./virtual";

/// The picture of a filter: the mark of the one state it asks for, a funnel
/// for tokens, a lens for words.
export function FilterIcon({ filter, dim }: { filter: Filter; dim?: boolean }) {
  const lone = filter.tokens.length === 1 && !filter.words.length && filter.tokens[0]!.k === TokenKey.State ? STATES[filter.tokens[0]!.v] : undefined;
  if (lone) {
    const level: Level = lone.length === 1 ? lone[0]! : Level.Action;
    return <Glyph level={level} />;
  }
  return <Icon name={filter.tokens.length ? "filter" : "search"} {...(dim ? { className: "kw-dim" } : {})} />;
}

const GROUP_KEY = { items: "group.items", hosts: "group.hosts", members: "group.members", clusters: "group.clusters" } as const;
const GROUPS: ResultGroup[] = [ResultGroup.Items, ResultGroup.Hosts, ResultGroup.Members, ResultGroup.Clusters];

/// A line of the calm list: a group's caption, or a found thing with its
/// place among the rows (what the arrows count).
type Line = { group: ResultGroup; n: number } | { id: string; k: number };
type Calm = { lines: Line[]; order: string[] };
const CALM = new WeakMap<readonly string[], Calm>();
function calmOf(dir: Directory, ids: readonly string[]): Calm {
  let c = CALM.get(ids);
  if (c) return c;
  const lines: Line[] = [];
  const order: string[] = [];
  for (const g of GROUPS) {
    const xs = ids.filter((id) => dir.node(id).result!.group === g);
    if (!xs.length) continue;
    lines.push({ group: g, n: xs.length });
    for (const id of xs) lines.push({ id, k: order.push(id) - 1 });
  }
  CALM.set(ids, (c = { lines, order }));
  return c;
}

/// The found things in the order the calm list shows them, grouped: what
/// the arrows walk and Enter opens.
export const calmOrder = (q: Query, column: Extract<Column, { type: ColumnType.Results }>): readonly string[] => calmOf(q.dir, q.results(column.scope, column.filter)).order;

/// Open a found thing: the path continues with it.
export function openFound(store: PathStore, id: string) {
  store.commitState({ segs: [...store.get().state.segs, { id }], map: null, verb: null, arg: "" });
}

/// How many of the calm list's first rows come in one by one.
const STAGGERED = 8;

/// The calm list's lines, laid out from the tokens: a caption, a row of two
/// lines, and the breath over a caption that follows a row.
const LAYOUTS = new WeakMap<Line[], RowLayout>();
function calmLayout(lines: Line[]): RowLayout {
  let l = LAYOUTS.get(lines);
  if (l) return l;
  const caption = tokenPx("--ctl");
  const row = tokenPx("--row-2");
  const breath = tokenPx("--u2");
  l = layoutOf(
    lines.length,
    (i) => ("group" in lines[i]! ? caption : row),
    (i) => (i > 0 && "group" in lines[i]! && "id" in lines[i - 1]! ? breath : 0),
  );
  LAYOUTS.set(lines, l);
  return l;
}
const NO_LAYOUT: RowLayout = layoutOf(0, () => 0, () => 0);
/// The calm list scrolls with the sheet it stands on.
function sheetOf(list: HTMLElement): HTMLElement {
  const sc = list.closest<HTMLElement>(".kw-insp");
  if (!sc) throw new Error("the calm list stands outside the inspector");
  return sc;
}

export function CalmList({ column, lsel }: { column: Extract<Column, { type: ColumnType.Results }>; lsel: number }) {
  const { dir, query, store, places, savePlace } = useCore();
  const snap = store.get();
  const ids = query.results(column.scope, column.filter);
  const saved = currentPlace(query, snap.state, places);
  const listRef = useRef<HTMLDivElement>(null);
  const calm = calmOf(dir, ids);
  const long = calm.lines.length > WINDOW_FROM;
  const layout = long ? calmLayout(calm.lines) : NO_LAYOUT;
  const [start, end] = useWindow(listRef, sheetOf, layout, long);
  // The first rows come in one after another when the list is drawn; once
  // the last of them has played the list holds still (a row drawn later, by
  // a scroll, just stands there).
  const [settled, setSettled] = useState(long);
  // The row the arrows stand on stays in sight; a windowed list may not have
  // drawn it, its place is known from the layout.
  useEffect(() => {
    const list = listRef.current;
    if (!list) return;
    if (!long) {
      void list.querySelector(".kw-lrow.kw-on")?.scrollIntoView({ block: "nearest" });
      return;
    }
    const at = calm.lines.findIndex((x) => "id" in x && x.k === lsel);
    if (at < 0) return;
    const sc = sheetOf(list);
    const y = nearestScroll(layout, at, offsetIn(list, sc), sc.scrollTop, sc.clientHeight);
    if (y !== null) sc.scrollTop = y;
    // Only a new row to stand on brings the list to it.
  }, [lsel]);
  const head = (
    <div className="kw-lhead">
      <span className="kw-lt">
        <FilterIcon filter={column.filter} dim />
        <h1 className="kw-h1">{query.filterName(column.filter)}</h1>
        <span className="kw-n">{t("count.matches", { n: ids.length })}</span>
      </span>
      {column.scope !== "root" && <span className="kw-faint">{t("ui.inScope", { place: text(dir.node(column.scope).name) })}</span>}
      {saved ? (
        <span className="kw-saved">
          <Icon name="markOn" />
          {text(saved.name)}
        </span>
      ) : (
        <button type="button" className="kw-btn kw-quiet" onClick={savePlace}>
          <Icon name="mark" />
          {t("savePlace")}
        </button>
      )}
    </div>
  );
  if (!ids.length)
    return (
      <>
        {head}
        <div className="kw-empty">
          <span>{t("ui.nothingFound")}</span>
          <span className="kw-faint">{t("ui.dropOne")}</span>
        </div>
      </>
    );
  const sp = long ? spacersOf(layout, [start, end]) : null;
  const shownRows = calm.lines.slice(start, end);
  let lastRow = -1;
  shownRows.forEach((x, i) => {
    if ("id" in x) lastRow = i;
  });
  return (
    <>
      {head}
      <div
        className={`kw-lrows${settled ? "" : " kw-stagger"}`}
        ref={listRef}
        onAnimationEnd={(e) => {
          if (e.animationName === "kw-lrow-in" && (e.target as HTMLElement).dataset.lastIn !== undefined) setSettled(true);
        }}
      >
        {sp && sp.above > 0 && <div style={{ height: sp.above }} aria-hidden />}
        {shownRows.map((x, i) => {
          if ("group" in x)
            return (
              <div key={`g:${x.group}`} className="kw-lgrp">
                <span>{t(GROUP_KEY[x.group])}</span>
                <span>{x.n}</span>
              </div>
            );
          const id = x.id;
          const n = dir.node(id);
          const k = x.k;
          const where = n.result!.place.map((p) => text(dir.node(p).name)).join(" › ");
          const sub = n.member ? n.member.email : n.sub ? text(n.sub) : "";
          const why = n.why ? text(n.why) : t(`level.${n.level}`);
          const plugin = n.kind === NodeKind.Plugin;
          return (
            <div
              key={id}
              className={`kw-lrow${k === lsel ? " kw-on" : ""}`}
              onClick={() => openFound(store, id)}
              {...(k < STAGGERED ? { style: { "--i": k } as React.CSSProperties } : {})}
              {...(i === lastRow ? { "data-last-in": "" } : {})}
            >
              <span className="kw-who">
                {plugin ? (
                  <span className="kw-tile kw-plain">
                    <Icon name={n.icon} />
                  </span>
                ) : (
                  <Tile lead={nodeLead(dir, id)} />
                )}
                <span className="kw-lbl">
                  <span className={`kw-t${n.mono ? " kw-mono" : ""}`}>{text(n.name)}</span>
                  <span className={`kw-s${n.mono || n.subMono ? " kw-mono" : ""}`}>{sub}</span>
                </span>
              </span>
              <span className="kw-why">{why}</span>
              <span className="kw-pl">{n.member ? `${where} · ${t(`role.${n.member.role}`)}` : where}</span>
              <Glyph level={n.level} words={why} />
            </div>
          );
        })}
        {sp && sp.below > 0 && <div style={{ height: sp.below }} aria-hidden />}
      </div>
    </>
  );
}
