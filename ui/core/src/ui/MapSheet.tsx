// The map sheet: a mode of the object, the widest sheet of the stack. The
// model comes from the graph; where its points stand is worked out by
// `map/layout.ts` from widths measured here. Points under the pointer light
// the paths through them (and their rows in the columns, through `onHover`);
// a click steps the columns to the point and keeps the map while it is on it.
import { useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { t, text } from "../i18n";
import { LEVEL_MARK } from "../model/signals";
import { Level, type LoudLevel } from "../model/types";
import { mapModel } from "../map/model";
import { type MapNode, EdgeKind } from "../map/types";
import {
  captionX,
  chipEdges,
  drawEdges,
  firstFit,
  laneWidths,
  nextFit,
  orient,
  overflow,
  paintCap,
  pathsThrough,
  placeLanes,
  placeNode,
  placeVertical,
  roleOf,
  type Fit,
  type LayoutTokens,
  type Placed,
  LaneRole,
} from "../map/layout";
import { objectOf, type MapRef } from "../path/query";
import { usePath } from "../path/store";
import { Icon, ShapeSvg } from "./Icons";
import { IconButton, Kbd, Mark, useCore, useLang } from "./marks";
import { NodeKind, MapKind } from "../path/directory";
import { Pending } from "./Loading";
import { enumParser } from "../model/enum";

/// A layout token in pixels, read once from the style sheet: the script's
/// numbers come from the same layout system as the CSS.
const TOKENS = new Map<string, number>();
function token(name: string): number {
  let v = TOKENS.get(name);
  if (v === undefined) {
    const probe = document.body.appendChild(document.createElement("div"));
    probe.style.cssText = `position:absolute;visibility:hidden;height:0;pointer-events:none;width:var(${name})`;
    v = probe.getBoundingClientRect().width;
    probe.remove();
    if (!(v > 0)) throw new Error(`layout token ${name} is missing`);
    TOKENS.set(name, v);
  }
  return v;
}
const readTokens = (): LayoutTokens => ({
  top: token("--map-top"),
  bottom: token("--map-bottom"),
  gap: token("--map-gap"),
  maxStep: token("--map-step"),
  minLaneGap: token("--u6"),
  maxLaneGap: token("--map-lane-gap"),
  minWidth: token("--map-min-w"),
  padX: token("--insp-gutter"),
  cap: token("--col-w"),
  u: token("--u"),
});

const POINT_CLASS: Record<Level, string> = { [Level.Critical]: "s-crit", [Level.Action]: "s-act", [Level.Warning]: "s-warn", [Level.Healthy]: "s-ok", [Level.Unknown]: "s-unk" };
const ROLE_CLASS: Record<LaneRole, string> = { [LaneRole.EndL]: "end-l", [LaneRole.EndR]: "end-r", [LaneRole.Pill]: "pill" };
const lineClass = (kind: string, level?: LoudLevel) => `ln p-${kind}${level ? ` lv-${level === Level.Critical ? "crit" : "warn"}` : ""}`;

/// A point's picture: initials for a person, the type's shape with the
/// state's mark inside for anything else.
function Point({ n }: { n: MapNode }) {
  if (n.avatar) return <span className={`av${n.invited ? " inv" : ""}`}>{n.avatar}</span>;
  if (!n.shape) throw new Error(`the point "${n.id}" has neither a shape nor initials`);
  return (
    <span className={`gl ${POINT_CLASS[n.level]}`}>
      <ShapeSvg shape={n.shape} />
      <i>{LEVEL_MARK[n.level]}</i>
    </span>
  );
}

/// A point's second line: its words, then its marks; a tight canvas keeps
/// only the marks.
function Sub({ n, compact, mono }: { n: MapNode; compact: boolean; mono: boolean }) {
  const marks = n.marks.map((m, i) => <Mark key={i} level={m.level} words={m.text} />);
  if (compact && marks.length) return <>{marks}</>;
  const s = text(n.sub);
  return (
    <>
      {s ? <span className={mono ? "mono" : undefined}>{marks.length ? t("mapui.subMarks", { sub: s }) : s}</span> : null}
      {marks}
    </>
  );
}

type Placement = { key: string; width: number; x: number[]; lw: number[]; placed: Map<string, Placed>; capX: number[] };

let models = 0;

/// Where the page's fonts stand (the browser's FontFaceSet.status).
enum FontsState {
  Loading = "loading",
  Loaded = "loaded",
}
const parseFontsState = enumParser(FontsState, "a state of the page's fonts");
const fontsState = (): FontsState => parseFontsState(document.fonts.status);

/// The most points a lane's skeleton shows while the map is built.
const BUILD_POINTS = 5;

export function MapSheet({ map, hover, onHover }: { map: MapRef; hover: string | null; onHover: (id: string | null) => void }) {
  const { dir, store } = useCore();
  const lang = useLang();
  const snap = usePath(store);
  const md = useMemo(() => mapModel(dir, map), [dir, map.kind, map.anchor]);
  const version = useMemo(() => ++models, [md]);
  const es = useMemo(() => orient(md), [md]);
  const T = useMemo(readTokens, []);
  const lanes = md.lanes.length;

  const obj = objectOf(snap.state.segs);
  const selected = obj && md.nodes.some((n) => n.id === obj) ? obj : null;
  const focus = hover ?? selected;
  const hi = focus && md.nodes.some((n) => n.id === focus) ? pathsThrough(es, focus) : null;

  const canvas = useRef<HTMLDivElement>(null);
  const nodeEls = useRef(new Map<string, HTMLDivElement>());
  const capEls = useRef<(HTMLDivElement | null)[]>([]);
  const [size, setSize] = useState<{ w: number; h: number } | null>(null);
  useLayoutEffect(() => {
    const el = canvas.current;
    if (!el) throw new Error("the map's canvas is not mounted");
    const read = () => setSize((s) => (s && s.w === el.clientWidth && s.h === el.clientHeight ? s : { w: el.clientWidth, h: el.clientHeight }));
    read();
    const ro = new ResizeObserver(read);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Widths are measured in the fonts of the moment: a web font that arrives
  // later changes them, so the map is fitted again once fonts are in.
  const [fonts, setFonts] = useState(0);
  useLayoutEffect(() => {
    const fs = document.fonts;
    let live = true;
    const again = () => live && setFonts((n) => n + 1);
    void fs.ready.then(again);
    fs.addEventListener("loadingdone", again);
    return () => {
      live = false;
      fs.removeEventListener("loadingdone", again);
    };
  }, []);

  const key = `${version}:${lang}:${fonts}:${size?.w ?? 0}x${size?.h ?? 0}`;
  const [fitState, setFit] = useState<{ key: string; fit: Fit }>({ key: "", fit: firstFit(T) });
  const fit = fitState.key === key ? fitState.fit : firstFit(T);
  const fitKey = `${key}:${fit.cap}:${fit.compact}:${fit.tries}`;
  const [placement, setPlacement] = useState<Placement | null>(null);
  const current = placement && placement.key === fitKey ? placement : null;
  const ys = useMemo(() => (size ? placeVertical(md, size.h, T) : null), [md, size, T]);
  const cap = paintCap(fit, T.u);

  // Measure the points at the current setting; give up detail, then width,
  // until the lanes fit; then place them. Each step re-renders before paint.
  useLayoutEffect(() => {
    if (!size || current) return;
    if (fitState.key !== key) {
      setFit({ key, fit: firstFit(T) });
      return;
    }
    const widths = new Map<string, number>();
    for (const n of md.nodes) {
      const el = nodeEls.current.get(n.id);
      if (!el) throw new Error(`the point "${n.id}" is not mounted`);
      widths.set(n.id, el.offsetWidth);
    }
    const capW = md.lanes.map((_, l) => {
      const el = capEls.current[l];
      if (!el) throw new Error(`the caption of lane ${l} is not mounted`);
      return Math.ceil(el.offsetWidth);
    });
    const lw = laneWidths(md, widths, capW);
    const room = Math.max(T.minWidth, size.w) - T.padX * 2;
    const nf = nextFit(fit, overflow(lw, room, T.minLaneGap), lanes, T.u);
    if (nf) {
      setFit({ key, fit: nf });
      return;
    }
    const { x, width } = placeLanes(lw, size.w, T);
    const placed = new Map(md.nodes.map((n) => [n.id, placeNode(roleOf(n.lane, lanes), x[n.lane]!, lw[n.lane]!, widths.get(n.id)!)]));
    const capX = md.lanes.map((_, l) => captionX(roleOf(l, lanes), x[l]!, lw[l]!, capW[l]!, width, T.padX));
    setPlacement({ key: fitKey, width, x, lw, placed, capX });
  });

  const drawn = current && ys ? drawEdges(es, current.placed, ys) : null;
  const chips = drawn ? chipEdges(es, hi, hover) : [];
  const present = md.legend.filter((l) => md.edges.some((e) => e.kind === l.kind && (l.level ? e.level === l.level : !e.level || e.kind === EdgeKind.Refused)));
  const fn = focus ? md.nodes.find((n) => n.id === focus) : undefined;
  // Until the points are placed in the fonts they will be drawn in, the
  // canvas shows the map's skeleton — its lanes and points as bars — over
  // the points being measured; then the map fades in.
  const building = !drawn || fontsState() === FontsState.Loading;
  const built = useRef(false);
  if (building) built.current = true;
  const perLane = md.lanes.map((_, l) => Math.min(BUILD_POINTS, md.nodes.filter((n) => n.lane === l).length));
  const subMono = (n: MapNode) => (n.nav ? dir.node(n.nav).subMono === true : false);

  return (
    <div className="msheet">
      <header className="mhead">
        <div className="mtop">
          <div className="mt">
            <h1>{text(md.title)}</h1>
            <div className="mplace">{text(md.place)}</div>
          </div>
          <div className="mlegend">
            {present.map((l, i) => (
              <span key={i}>
                <svg viewBox="0 0 24 8" aria-hidden="true">
                  <path className={lineClass(l.kind, l.level)} d="M0 4H24" />
                </svg>
                {text(l.text)}
              </span>
            ))}
          </div>
          <IconButton icon="close" tip={t("mapui.closeMap")} className="tip-l" onClick={() => store.closeMap()} />
        </div>
        <div className="finds">
          {md.findings.map((f, i) => (
            <button
              type="button"
              key={i}
              className={`find${f.focus === focus ? " on" : ""}`}
              onMouseEnter={() => onHover(f.focus)}
              onMouseLeave={() => onHover(null)}
              onClick={() => store.go(f.focus)}
            >
              <Mark level={f.level} words={f.text} />
            </button>
          ))}
        </div>
      </header>
      <div className={`mcanvas${building ? " building" : built.current ? " built" : ""}`} ref={canvas}>
        {building && (
          <div className="mbuild sk-late" aria-hidden="true">
            {perLane.map((k, l) => (
              <div key={l} className="mbuild-lane">
                <span className="sk sk-caption" />
                {Array.from({ length: k }, (_, i) => (
                  <span key={i} className="mbuild-pt">
                    <span className="sk mbuild-dot" />
                    <span className="sk-two">
                      <span className="sk sk-name" />
                      <span className="sk sk-sub" />
                    </span>
                  </span>
                ))}
              </div>
            ))}
          </div>
        )}
        {building && (
          <div className="mbuild-say">
            <Pending words={t("load.map")} />
          </div>
        )}
        {drawn && current && size ? (
          <svg key={`${map.kind}:${map.anchor}`} className="medges fresh" viewBox={`0 0 ${current.width} ${size.h}`} style={{ width: current.width }}>
            {drawn.lines.map((l, i) => (
              <path key={i} className={`${lineClass(l.edge.kind, l.edge.level)}${hi ? (hi.edges.has(i) ? " lit" : " faded") : ""}`} d={l.d} />
            ))}
            {drawn.ports.map((p) => (
              <circle key={`${p.id}:${p.x}`} className={`port${hi && !hi.nodes.has(p.id) ? " faded" : ""}`} cx={p.x} cy={p.y} r={2} />
            ))}
          </svg>
        ) : (
          <svg className="medges" />
        )}
        <div className="mlanes">
          {md.lanes.map((name, l) => (
            <div
              key={l}
              className="lane-h"
              ref={(el) => {
                capEls.current[l] = el;
              }}
              style={current ? { left: current.capX[l] } : undefined}
            >
              {text(name)}
              <span className="n">{md.nodes.filter((n) => n.lane === l).length}</span>
            </div>
          ))}
        </div>
        <div className="mnodes">
          {md.nodes.map((n) => {
            const role = roleOf(n.lane, lanes);
            const p = current?.placed.get(n.id);
            const style = { top: ys?.get(n.id) ?? 0, ...(p ? { left: p.left, ...(p.width !== null ? { width: p.width } : {}) } : {}), "--lbw": `${role === LaneRole.Pill ? cap - 48 : cap - 32}px` } as CSSProperties;
            const cls = ["nd", ROLE_CLASS[role], n.anchor ? "anchor" : "", hi && !hi.nodes.has(n.id) ? "faded" : "", n.id === selected ? "sel" : ""].filter(Boolean).join(" ");
            return (
              <div
                key={n.id}
                className={cls}
                style={style}
                ref={(el) => {
                  if (el) nodeEls.current.set(n.id, el);
                  else nodeEls.current.delete(n.id);
                }}
                onMouseEnter={() => onHover(n.id)}
                onMouseLeave={() => onHover(null)}
                onClick={n.nav ? () => store.go(n.nav!) : undefined}
              >
                <Point n={n} />
                <span className="lb">
                  <b className={n.mono ? "mono" : undefined}>{text(n.label)}</b>
                  <em className="calm">
                    <Sub n={n} compact={fit.compact} mono={subMono(n)} />
                  </em>
                </span>
              </div>
            );
          })}
        </div>
        <div className="mchips">
          {drawn &&
            chips.map((i) => {
              const l = drawn.lines[i]!;
              const e = l.edge;
              return (
                <span key={i} className={`ec calm${e.level === Level.Critical ? " crit" : ""}`} style={{ left: Math.round(l.mid[0]), top: Math.round(l.mid[1]) }}>
                  {e.level ? <Mark level={e.level} words={e.words} /> : text(e.words)}
                </span>
              );
            })}
        </div>
      </div>
      <footer className="mfoot">
        {fn ? (
          <>
            <span className="cur">
              <Point n={fn} />
              <span className="tx">
                <b>{text(fn.label)}</b>
                <span className="calm">
                  <Sub n={fn} compact={false} mono={subMono(fn)} />
                </span>
              </span>
            </span>
            {fn.nav && dir.node(fn.nav).kind === NodeKind.Item && !(map.kind === MapKind.Relations && map.anchor === fn.nav) ? (
              <button type="button" className="btn" onClick={() => store.openMap({ kind: MapKind.Relations, anchor: fn.nav! })}>
                <Icon name="map" />
                {t("mapui.itsRelations")}
              </button>
            ) : null}
            {fn.nav ? (
              <button type="button" className="btn quiet" onClick={() => store.go(fn.nav!)}>
                {t("mapui.open")}
                <Kbd>↵</Kbd>
              </button>
            ) : null}
          </>
        ) : (
          <>
            <span className="cur">
              <span className="faint">{t("mapui.counts", { points: { key: "mapui.points", args: { n: md.nodes.length } }, links: { key: "mapui.links", args: { n: md.edges.length } } })}</span>
            </span>
            <span className="hint">
              <span>{t("mapui.hoverPaths")}</span>
              <span>{t("mapui.clickPick")}</span>
              <span>
                <Kbd>↵</Kbd>
                {t("mapui.open")}
              </span>
              <span>
                <Kbd>Esc</Kbd>
                {t("mapui.close")}
              </span>
            </span>
          </>
        )}
      </footer>
    </div>
  );
}
