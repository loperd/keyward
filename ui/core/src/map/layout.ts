// Where a map's points stand, worked out from the model and measured widths.
// Vertically the pivot lane is spread evenly and every other lane follows the
// mean of its already placed neighbours, then is pushed apart; horizontally
// each lane is as wide as its widest point (or its caption) and the lanes are
// spread with equal gaps and centred. Measuring is the component's job: every
// function here takes widths and sizes as numbers, so the algorithm is pure
// and the same at any size. Every number comes from the layout tokens.
import type { MapEdge, MapModel } from "./types";

/// The layout system's numbers, read by the component from the CSS tokens.
export type LayoutTokens = {
  /// Where the first point may stand, and the least room under the last.
  top: number;
  bottom: number;
  /// The least step between points of a lane, and the most for the pivot.
  gap: number;
  maxStep: number;
  /// The least and the most gap between lanes.
  minLaneGap: number;
  maxLaneGap: number;
  /// The least canvas width the map is laid out for.
  minWidth: number;
  /// The inspector's gutter on either side.
  padX: number;
  /// A label's widest measure before it is capped, and the unit.
  cap: number;
  u: number;
};

/// The outer lanes read towards the middle: the left lane's text ends at its
/// point, the right lane's starts at it; the lanes between are pills.
export enum LaneRole {
  EndL = "endL",
  EndR = "endR",
  Pill = "pill",
}
export const roleOf = (lane: number, lanes: number): LaneRole => (lane === 0 ? LaneRole.EndL : lane === lanes - 1 ? LaneRole.EndR : LaneRole.Pill);

/// Push wanted positions apart by `gap`, keep their mean, then bring the whole
/// run inside [top, bottom] and onto the 4px half-step.
export function spread(want: number[], gap: number, top: number, bot: number): number[] {
  const order = want.map((y, i) => ({ y, i })).sort((p, q) => p.y - q.y || p.i - q.i);
  const ys = order.map((o) => o.y);
  for (let i = 1; i < ys.length; i++) ys[i] = Math.max(ys[i]!, ys[i - 1]! + gap);
  const shift = order.reduce((s, o, i) => s + (o.y - ys[i]!), 0) / (ys.length || 1);
  const lo = ys[0]! + shift;
  const hi = ys[ys.length - 1]! + shift;
  let fix = 0;
  if (lo < top) fix = top - lo;
  else if (hi > bot) fix = Math.max(top - lo, bot - hi);
  const out = new Array<number>(want.length);
  order.forEach((o, i) => (out[o.i] = Math.round((ys[i]! + shift + fix) / 4) * 4));
  return out;
}

/// Each point's neighbours, in the order of the edges: one walk over them
/// instead of one per point.
function neighbourMap(md: MapModel): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const add = (id: string, other: string) => {
    const xs = out.get(id);
    if (xs) xs.push(other);
    else out.set(id, [other]);
  };
  for (const e of md.edges) {
    add(e.a, e.b);
    if (e.b !== e.a) add(e.b, e.a);
  }
  return out;
}

/// Every point's y on a canvas of `height`.
export function placeVertical(md: MapModel, height: number, t: Pick<LayoutTokens, "top" | "bottom" | "gap" | "maxStep">): Map<string, number> {
  const top = t.top;
  const bot = height - t.bottom;
  const pos = new Map<string, number>();
  const lanes = md.lanes.length;
  const near = neighbourMap(md);
  const byLane = (l: number) => md.nodes.filter((n) => n.lane === l);
  const pl = byLane(md.pivot);
  const step = Math.max(t.gap, Math.min(t.maxStep, Math.floor((bot - top) / Math.max(1, pl.length - 1 || 1) / 8) * 8));
  const span = step * (pl.length - 1);
  pl.forEach((n, i) => pos.set(n.id, Math.round(top + (bot - top - span) / 2 + i * step)));
  const order = [...Array(lanes).keys()].filter((l) => l !== md.pivot).sort((a, b) => Math.abs(a - md.pivot) - Math.abs(b - md.pivot) || a - b);
  for (const l of order) {
    const list = byLane(l);
    if (!list.length) continue;
    const placedMax = pos.size ? Math.max(...pos.values()) : top - t.gap;
    const want = list.map((n) => {
      const ys = (near.get(n.id) ?? []).filter((x) => pos.has(x)).map((x) => pos.get(x)!);
      return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : placedMax + t.gap;
    });
    spread(want, t.gap, top, bot).forEach((y, i) => pos.set(list[i]!.id, y));
  }
  return pos;
}

/// A lane is as wide as its widest point or its caption, whichever is wider:
/// no caption is cut.
export function laneWidths(md: MapModel, nodeWidths: ReadonlyMap<string, number>, captionWidths: number[]): number[] {
  const lw = captionWidths.slice();
  for (const n of md.nodes) {
    const w = nodeWidths.get(n.id);
    if (w === undefined) throw new Error(`the point "${n.id}" was not measured`);
    lw[n.lane] = Math.max(lw[n.lane] ?? 0, Math.ceil(w));
  }
  return lw;
}

/// How far the lanes at their narrowest gaps run past the room.
export const overflow = (lw: number[], room: number, minLaneGap: number) => lw.reduce((a, b) => a + b, 0) + minLaneGap * (lw.length - 1) - room;

/// The labels' setting while the map is fitted: the cap of a label, whether
/// the second line keeps only its marks, and how many times the cap shrank.
export type Fit = { cap: number; compact: boolean; tries: number };
export const firstFit = (t: Pick<LayoutTokens, "cap">): Fit => ({ cap: t.cap, compact: false, tries: 0 });
/// The cap a label is painted at: never below 18 units.
export const paintCap = (f: Fit, u: number) => Math.max(u * 18, f.cap);
/// The next setting to try when the lanes do not fit, or `null` when they do
/// (or nothing more can be given up). Room is found by narrowing the gaps
/// first; a tight canvas then drops the second line's detail and keeps its
/// marks; only then are labels capped, at most four times.
export function nextFit(f: Fit, over: number, lanes: number, u: number): Fit | null {
  if (over <= 0) return null;
  if (!f.compact) return { cap: f.cap, compact: true, tries: 0 };
  if (f.tries >= 4) return null;
  return { cap: f.cap - Math.ceil(over / lanes) - u, compact: true, tries: f.tries + 1 };
}

/// The lanes' left edges: equal gaps, the whole centred on the canvas.
export function placeLanes(lw: number[], width: number, t: Pick<LayoutTokens, "padX" | "minLaneGap" | "maxLaneGap" | "minWidth">): { x: number[]; gap: number; width: number } {
  const wc = Math.max(t.minWidth, width);
  const room = wc - t.padX * 2;
  const sum = lw.reduce((a, b) => a + b, 0);
  const gap = Math.min(t.maxLaneGap, Math.max(t.minLaneGap, Math.floor((room - sum) / Math.max(1, lw.length - 1))));
  const x: number[] = [];
  let at = Math.round((wc - sum - gap * (lw.length - 1)) / 2);
  for (const w of lw) {
    x.push(at);
    at += w + gap;
  }
  return { x, gap, width: wc };
}

/// A point's box and ports: a pill takes its lane's width, the left lane's
/// point ends on the lane's right edge, the right lane's starts on its left.
/// The outer lanes' ports stand a half-step off the text.
export type Placed = { left: number; width: number | null; portL: number | null; portR: number | null };
export function placeNode(role: LaneRole, x0: number, laneW: number, nodeW: number): Placed {
  const x1 = x0 + laneW;
  if (role === LaneRole.Pill) return { left: x0, width: laneW, portL: x0, portR: x1 };
  if (role === LaneRole.EndL) return { left: x1 - nodeW, width: null, portL: null, portR: x1 + 4 };
  return { left: x0, width: null, portL: x0 - 4, portR: null };
}

/// A lane's caption stands over its text edge: right for the left lane, left
/// for the right one, centred over pills; never outside the gutters.
export function captionX(role: LaneRole, x0: number, laneW: number, capW: number, wc: number, padX: number): number {
  const x = role === LaneRole.EndL ? x0 + laneW - capW : role === LaneRole.EndR ? x0 : x0 + (laneW - capW) / 2;
  return Math.round(Math.max(padX, Math.min(wc - padX - capW, x)));
}

/// A line: a horizontal bezier from the left point's right port to the right
/// point's left port.
export function edgePath(x1: number, y1: number, x2: number, y2: number): { d: string; mid: [number, number] } {
  const dx = Math.max(24, (x2 - x1) * 0.5);
  return { d: `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`, mid: [(x1 + x2) / 2, (y1 + y2) / 2] };
}

/// An edge oriented left to right by lane.
export type Oriented = MapEdge & { L: string; R: string };
export function orient(md: MapModel): Oriented[] {
  const lane = new Map(md.nodes.map((n) => [n.id, n.lane]));
  return md.edges.map((e) => {
    const la = lane.get(e.a);
    const lb = lane.get(e.b);
    if (la === undefined || lb === undefined) throw new Error(`an edge of the map joins a point it does not have: ${e.a} → ${e.b}`);
    return la < lb ? { ...e, L: e.a, R: e.b } : { ...e, L: e.b, R: e.a };
  });
}

/// The edges as drawn, with the ports they end on.
export function drawEdges(es: Oriented[], placed: ReadonlyMap<string, Placed>, ys: ReadonlyMap<string, number>) {
  const ports = new Map<string, { id: string; x: number; y: number }>();
  const lines = es.map((e) => {
    const a = placed.get(e.L)!;
    const b = placed.get(e.R)!;
    if (a.portR === null || b.portL === null) throw new Error(`the edge ${e.L} → ${e.R} runs against its lanes`);
    const y1 = ys.get(e.L)!;
    const y2 = ys.get(e.R)!;
    ports.set(`${e.L}r`, { id: e.L, x: a.portR, y: y1 });
    ports.set(`${e.R}l`, { id: e.R, x: b.portL, y: y2 });
    return { ...edgePath(a.portR, y1, b.portL, y2), edge: e };
  });
  return { lines, ports: [...ports.values()] };
}

/// The paths through a point: rightwards along rightward edges, leftwards
/// along leftward ones — what the point reaches and what reaches it.
export function pathsThrough(es: Oriented[], id: string): { nodes: Set<string>; edges: Set<number> } {
  const nodes = new Set([id]);
  const edges = new Set<number>();
  // The edges leaving each point either way, in their order: the walk reads
  // a point's own edges, not every edge at every step.
  const out = { 1: new Map<string, number[]>(), [-1]: new Map<string, number[]>() } as Record<1 | -1, Map<string, number[]>>;
  es.forEach((e, i) => {
    for (const [d, near] of [[1, e.L], [-1, e.R]] as const) {
      const xs = out[d].get(near);
      if (xs) xs.push(i);
      else out[d].set(near, [i]);
    }
  });
  const walk = (from: string, dir: 1 | -1) => {
    for (const i of out[dir].get(from) ?? []) {
      const e = es[i]!;
      const far = dir > 0 ? e.R : e.L;
      if (!edges.has(i)) {
        edges.add(i);
        nodes.add(far);
        walk(far, dir);
      }
    }
  };
  walk(id, 1);
  walk(id, -1);
  return { nodes, edges };
}

/// Words on a line only where they matter: always on a line marked for it
/// (a critical one) unless the focus dims it, and on the lines touching the
/// point under the pointer when it has few enough to read.
export function chipEdges(es: Oriented[], hi: { edges: Set<number> } | null, hover: string | null): number[] {
  const touching = hover ? es.filter((e) => e.a === hover || e.b === hover).length : 0;
  return es
    .map((e, i) => ({ e, i }))
    .filter(({ e, i }) => (e.chip && (!hi || hi.edges.has(i))) || (hover !== null && (e.a === hover || e.b === hover) && touching <= 6))
    .map(({ i }) => i);
}
