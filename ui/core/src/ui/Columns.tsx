// The stack of sheets: a list column per step of the path, the last two open,
// every earlier one folded into a spine. A selection is a folder tab running
// into the next sheet; the focused column carries a bar beside it.
import { useEffect, useLayoutEffect, useRef } from "react";
import { text } from "../i18n";
import { isStep, type Directory, type Entry, type Node, ResultGroup, NodeKind } from "../path/directory";
import { rows, type Column, ColumnType } from "../path/query";
import { Icon } from "./Icons";
import { Glyph, Tile, isLoudLevel, nodeLead, useCore } from "./marks";
import { FilterIcon } from "./CalmList";
import { t } from "../i18n";
import { tokenPx } from "./tokens";
import { WINDOW_FROM, layoutOf, nearestScroll, offsetIn, spacersOf, useWindow, type RowLayout } from "./virtual";
import { useRowMotion, withGone } from "./row-motion";
import { LeadTile } from "../doc/spec";
import { Level } from "../model/types";

/// A column's tier: deeper columns stand nearer the top sheet.
const tierOf = (i: number, n: number) => (n <= 1 ? 40 : Math.round(12 + (68 * i) / (n - 1)));
const bgOf = (k: number) => `color-mix(in srgb, var(--tier-hi) ${k}%, var(--tier-lo))`;

export const columnKey = (c: Column, q: ReturnType<typeof useCore>["query"]) =>
  c.type === ColumnType.Results ? `res:${c.scope}:${q.serialize({ segs: [{ filter: c.filter }], map: null, verb: null, arg: "" })}` : `kids:${c.parent}`;

function Tail({ n }: { n: Node }) {
  if (n.level === Level.Unknown && (n.member || n.result?.group === ResultGroup.Hosts)) return <Glyph level={Level.Unknown} {...(n.why ? { words: n.why } : {})} />;
  if (!isLoudLevel(n.level)) return null;
  return <Glyph level={n.level} {...(n.why ? { words: n.why } : {})} />;
}

/// How a row moves: still, lit up (it came or changed), or folding away.
enum Move {
  Still = "still",
  Fresh = "fresh",
  Gone = "gone",
}
const MOVE_CLASS: Record<Move, string> = { [Move.Still]: "", [Move.Fresh]: " arrive", [Move.Gone]: " leave" };

function Row({ e, sel, col, lit, onHover, move = Move.Still, onSettle }: { e: Entry; sel: string | null; col: Column; lit: boolean; onHover: (id: string | null) => void; move?: Move; onSettle?: (id: string) => void }) {
  const { dir, query, store } = useCore();
  if ("gap" in e) return <div className="gap" />;
  if ("heading" in e)
    return (
      <div className="grp">
        {text(e.heading)}
        {e.count !== undefined && <span className="n">{e.count}</span>}
      </div>
    );
  if ("place" in e) {
    const p = dir.place(e.place);
    const st = query.compile(p.line);
    const last = st.segs[st.segs.length - 1];
    const before = st.segs[st.segs.length - 2];
    const n = last && "filter" in last ? query.results(before && "id" in before ? before.id : "root", last.filter).length : null;
    return (
      <div className="row cont" onClick={() => store.commit(p.line)}>
        <span className="lead">{p.level ? <Glyph level={p.level} /> : <Tile lead={{ tile: LeadTile.Plain, icon: p.icon! }} />}</span>
        <span className="lbl">
          <span className="t">{text(p.name)}</span>
        </span>
        <span className="side">{n !== null && <span className="n">{n}</span>}</span>
      </div>
    );
  }
  const n = dir.node(e.id);
  const isSel = e.id === sel && move !== Move.Gone;
  const base = `row${isSel ? " sel" : ""}${e.off ? " off" : ""}${lit ? " lit" : ""}${MOVE_CLASS[move]}`;
  const choose = () => store.choose(col.at, e.id);
  const id = e.id;
  const hover = {
    onMouseEnter: () => onHover(id),
    onMouseLeave: () => onHover(null),
    ...(move !== Move.Still && onSettle
      ? {
          onAnimationEnd: (ev: React.AnimationEvent) => {
            if (ev.target === ev.currentTarget) onSettle(id);
          },
        }
      : {}),
  };
  if (n.item || n.member || n.result) {
    const bare = n.kind === NodeKind.Plugin;
    return (
      <div className={`${base} two`} onClick={choose} {...hover} data-id={e.id}>
        <span className="lead">{bare ? <Icon name={n.icon} /> : <Tile lead={nodeLead(dir, e.id)} />}</span>
        <span className="lbl">
          <span className={`t${n.mono ? " mono" : ""}`}>{text(n.rowName ?? n.name)}</span>
          <span className={`s${n.subMono ? " mono" : ""}`}>{n.sub ? text(n.sub) : ""}</span>
        </span>
        <span className="side">
          <Tail n={n} />
        </span>
      </div>
    );
  }
  const sub = e.sub ?? n.sub;
  const lead = n.kind === NodeKind.Org ? <Tile lead={nodeLead(dir, e.id)} /> : <Tile lead={{ tile: LeadTile.Plain, icon: n.icon }} />;
  return (
    <div className={`${base} cont${sub ? " two" : ""}`} onClick={choose} {...hover} data-id={e.id}>
      <span className="lead">{lead}</span>
      <span className="lbl">
        <span className="t">{text(n.name)}</span>
        {sub && <span className="s">{text(sub)}</span>}
      </span>
      <span className="side">
        {e.off ? <Glyph level={Level.Unknown} words={t("perm.none")} /> : isLoudLevel(n.level) ? <Glyph level={n.level} words={{ key: `level.${n.level}` }} /> : null}
        {n.count !== undefined && !sub && <span className="n">{n.count}</span>}
      </span>
    </div>
  );
}

/// A row of two lines: what a filter finds, or a step with a second line.
const twoLines = (n: Node, e: Entry) => !!(n.item || n.member || n.result) || !!((isStep(e) ? e.sub : undefined) ?? n.sub);

/// A long column's rows, laid out from the tokens the style sheet sizes
/// them by: a row of one line or two, a caption, a breath; the first row of
/// one line stands lower, on the first line of a two-line row.
const LAYOUTS = new WeakMap<readonly Entry[], RowLayout>();
function columnLayout(dir: Directory, entries: readonly Entry[]): RowLayout {
  let l = LAYOUTS.get(entries);
  if (l) return l;
  const r1 = tokenPx("--row-1");
  const r2 = tokenPx("--row-2");
  const caption = tokenPx("--ctl");
  const breath = tokenPx("--u2");
  const height = (e: Entry) => ("gap" in e ? breath : "heading" in e ? caption : "place" in e ? r1 : twoLines(dir.node(e.id), e) ? r2 : r1);
  const first = entries[0];
  const lower = first && ("place" in first || (isStep(first) && !twoLines(dir.node(first.id), first))) ? (r2 - r1) / 2 : 0;
  l = layoutOf(entries.length, (i) => height(entries[i]!), (i) => (i === 0 ? lower : 0));
  LAYOUTS.set(entries, l);
  return l;
}
const NO_LAYOUT: RowLayout = layoutOf(0, () => 0, () => 0);
const itself = (el: HTMLElement) => el;

/// What a row shows, as far as its motion goes: a change of it lights it up.
const sigOf = (dir: Directory) => (e: Entry) => {
  if (!isStep(e)) return "";
  const n = dir.node(e.id);
  return `${text(n.rowName ?? n.name)}\u0000${n.sub ? text(n.sub) : ""}\u0000${n.level}\u0000${e.off ? 1 : 0}`;
};
const stepId = (e: Entry) => (isStep(e) ? e.id : null);

/// A column's list: whole while it is short, windowed while it is long. A
/// short list's rows move as they come, change and go; the selection is one
/// folder tab that glides from row to row.
function ColumnList({ entries, col, lit, onHover }: { entries: readonly Entry[]; col: Column; lit: string | null; onHover: (id: string | null) => void }) {
  const { dir } = useCore();
  const ref = useRef<HTMLDivElement>(null);
  const tab = useRef<HTMLDivElement>(null);
  const placed = useRef(false);
  const long = entries.length > WINDOW_FROM;
  const layout = long ? columnLayout(dir, entries) : NO_LAYOUT;
  const [start, end] = useWindow(ref, itself, layout, long);
  const sp = long ? spacersOf(layout, [start, end]) : null;
  const motion = useRowMotion(entries, stepId, sigOf(dir), !long);
  const drawn = long ? entries.slice(start, end).map((item) => ({ item, gone: false })) : withGone(entries, motion.gone.filter((g) => isStep(g.item) && dir.has(g.item.id)));
  // The tab stands under the selected row, read from the page before it is
  // painted; it glides when the selection moves within the list, and is
  // simply put there the first time.
  useLayoutEffect(() => {
    const list = ref.current;
    const slab = tab.current;
    if (!list || !slab) return;
    const row = list.querySelector<HTMLElement>(":scope > .row.sel");
    if (!row) {
      slab.style.opacity = "0";
      placed.current = false;
      return;
    }
    const first = !placed.current;
    if (first) slab.style.transition = "none";
    slab.style.transform = `translateY(${row.offsetTop}px)`;
    slab.style.height = `${row.offsetHeight}px`;
    slab.style.opacity = "1";
    if (first) {
      void slab.offsetHeight;
      slab.style.transition = "";
      placed.current = true;
    }
  });
  return (
    <div className="list" ref={ref} {...(long ? { "data-virtual": "" } : {})}>
      {sp && sp.above > 0 && <div style={{ height: sp.above }} aria-hidden />}
      {drawn.map(({ item: e, gone }, k) => {
        const move: Move = gone ? Move.Gone : isStep(e) && motion.fresh(e.id) ? Move.Fresh : Move.Still;
        return (
          <Row
            key={isStep(e) ? `${gone ? "gone:" : ""}${e.id}` : `${start + k}`}
            e={e}
            sel={col.sel}
            col={col}
            lit={isStep(e) && e.id === lit}
            onHover={onHover}
            move={move}
            onSettle={motion.settle}
          />
        );
      })}
      {sp && sp.below > 0 && <div style={{ height: sp.below }} aria-hidden />}
      <div className="tabsel" ref={tab} aria-hidden />
    </div>
  );
}

function Spine({ col, i }: { col: Column; i: number }) {
  const { dir, query, store } = useCore();
  // A spine names what its column holds (its parent, or the filter), so two
  // folded columns never read the same; the root's column is the vault.
  const id = col.type === ColumnType.Kids ? col.parent : null;
  const n = id ? dir.node(id) : null;
  const label = n ? text(n.name) : col.type === ColumnType.Results ? query.filterName(col.filter) : "";
  const lead =
    !n && col.type === ColumnType.Results ? (
      <span className="tile plain">
        <FilterIcon filter={col.filter} />
      </span>
    ) : n && (n.item || n.member || n.kind === NodeKind.Org) ? (
      <Tile lead={nodeLead(dir, n.id)} />
    ) : (
      <Tile lead={{ tile: LeadTile.Plain, icon: n?.icon ?? "folder" }} />
    );
  return (
    <div className="spine" title={label} onClick={() => store.expand(i)}>
      <span className="sp-ic">{lead}</span>
      <span className="sp-t">{label}</span>
      {n && isLoudLevel(n.level) ? (
        <span className="sp-g">
          <Glyph level={n.level} />
        </span>
      ) : (
        <span />
      )}
    </div>
  );
}

export function Columns({
  cols,
  open,
  widths,
  focus,
  lit,
  onHover,
}: {
  cols: Column[];
  open: boolean[];
  widths: { col: number; spine: number };
  focus: number;
  lit: string | null;
  onHover: (id: string | null) => void;
}) {
  const { dir, query } = useCore();
  const prev = useRef<string[]>([]);
  const ref = useRef<HTMLDivElement>(null);
  const keys = cols.map((c) => columnKey(c, query));
  const seen = prev.current;
  useEffect(() => {
    prev.current = keys;
  });
  // The focused selection stays in sight as the arrows walk. A windowed list
  // may not have drawn it: its place is known from the layout.
  useEffect(() => {
    const raf = requestAnimationFrame(() => {
      const list = ref.current?.querySelector<HTMLElement>(`.col[data-col="${focus}"] .list`);
      const c = cols[focus];
      if (!list || !c) return;
      if (list.dataset.virtual === undefined) {
        void list.querySelector(".row.sel")?.scrollIntoView({ block: "nearest" });
        return;
      }
      const entries = rows(query, c);
      const at = c.sel === null ? -1 : entries.findIndex((e) => isStep(e) && e.id === c.sel);
      if (at < 0) return;
      const y = nearestScroll(columnLayout(dir, entries), at, offsetIn(list, list), list.scrollTop, list.clientHeight);
      if (y !== null) list.scrollTop = y;
    });
    return () => cancelAnimationFrame(raf);
  });
  const n = cols.length;
  return (
    <div className="cols" ref={ref}>
      {cols.map((c, i) => {
        const key = keys[i]!;
        const fresh = seen.length > 0 && !seen.includes(key);
        const entries = rows(query, c);
        const shown = entries.length ? entries : null;
        return (
          <section
            key={key}
            data-col={i}
            className={`col${i === focus ? " focus" : ""}${open[i] ? "" : " spined"}${fresh ? " enter" : ""}`}
            style={
              {
                width: open[i] ? widths.col : widths.spine,
                zIndex: i + 1,
                "--bg": bgOf(tierOf(i, n)),
                "--tab": i + 1 < n ? bgOf(tierOf(i + 1, n)) : "var(--tier-hi)",
              } as React.CSSProperties
            }
          >
            <Spine col={c} i={i} />
            {shown ? (
              <ColumnList entries={shown} col={c} lit={lit} onHover={onHover} />
            ) : (
              <div className="list">
                <div className="row empty">{t("ui.nothingShort")}</div>
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
}
