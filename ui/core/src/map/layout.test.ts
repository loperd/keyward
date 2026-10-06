import { describe, expect, it } from "vitest";
import { DEMO, DEMO_NOW } from "../demo";
import { demoContributions } from "../demo-backend";
import { Directory, MapKind } from "../path/directory";
import { mapModel } from "./model";
import { type MapModel, type MapNode, EdgeKind } from "./types";
import {
  captionX,
  chipEdges,
  drawEdges,
  edgePath,
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
  spread,
  type LayoutTokens,
  LaneRole,
} from "./layout";
import { Level } from "../model/types";

const T: LayoutTokens = { top: 72, bottom: 32, gap: 56, maxStep: 136, minLaneGap: 48, maxLaneGap: 320, minWidth: 560, padX: 40, cap: 288, u: 8 };
const pt = (id: string, lane: number): MapNode => ({ id, lane, nav: id, level: Level.Healthy, label: { raw: id }, sub: { raw: "" }, marks: [] });
const model = (nodes: MapNode[], edges: [string, string][], lanes: number, pivot: number, chip: string[] = []): MapModel => ({
  nodes,
  edges: edges.map(([a, b]) => ({ a, b, kind: EdgeKind.In, words: { raw: "" }, ...(chip.includes(`${a}-${b}`) ? { chip: true, level: Level.Critical } : {}) })),
  lanes: Array.from({ length: lanes }, (_, i) => ({ raw: `lane ${i}` })),
  pivot,
  title: { raw: "" },
  place: { raw: "" },
  findings: [],
  legend: [],
});

describe("vertical placement", () => {
  it("spreads the pivot lane evenly and centres it", () => {
    const md = model([pt("a", 0), pt("b", 0), pt("c", 0)], [], 1, 0);
    const ys = placeVertical(md, 900, T);
    const v = ["a", "b", "c"].map((x) => ys.get(x)!);
    expect(v[1]! - v[0]!).toBe(v[2]! - v[1]!);
    expect(v[1]! - v[0]!).toBe(136);
    expect((v[0]! + v[2]!) / 2).toBe((72 + 900 - 32) / 2);
  });
  it("lets a lane follow the mean of its placed neighbours", () => {
    const md = model([pt("a", 0), pt("b", 0), pt("x", 1)], [["a", "x"], ["b", "x"]], 2, 0);
    const ys = placeVertical(md, 900, T);
    expect(ys.get("x")).toBe(Math.round(((ys.get("a")! + ys.get("b")!) / 2) / 4) * 4);
  });
  it("keeps points of a lane a gap apart and inside the canvas", () => {
    const ys = spread([100, 100, 100, 100], 56, 72, 400);
    const s = [...ys].sort((a, b) => a - b);
    for (let i = 1; i < s.length; i++) expect(s[i]! - s[i - 1]!).toBeGreaterThanOrEqual(56);
    expect(s[0]).toBeGreaterThanOrEqual(72);
    expect(ys.every((y) => y % 4 === 0)).toBe(true);
  });
});

describe("fitting", () => {
  it("goes compact first, then shrinks the cap at most four times", () => {
    let f = firstFit(T);
    f = nextFit(f, 100, 4, 8)!;
    expect(f).toEqual({ cap: 288, compact: true, tries: 0 });
    f = nextFit(f, 100, 4, 8)!;
    expect(f.cap).toBe(288 - 25 - 8);
    for (let i = 0; i < 3; i++) f = nextFit(f, 100, 4, 8)!;
    expect(f.tries).toBe(4);
    expect(nextFit(f, 100, 4, 8)).toBeNull();
    expect(nextFit(firstFit(T), 0, 4, 8)).toBeNull();
    expect(paintCap({ cap: 10, compact: true, tries: 4 }, 8)).toBe(144);
  });
  it("measures a lane by its widest point or its caption", () => {
    const md = model([pt("a", 0), pt("b", 0), pt("c", 1)], [], 2, 0);
    expect(laneWidths(md, new Map([["a", 100], ["b", 140.2], ["c", 30]]), [50, 60])).toEqual([141, 60]);
    expect(() => laneWidths(md, new Map([["a", 1]]), [0, 0])).toThrow();
    expect(overflow([100, 100], 100, 48)).toBe(148);
  });
});

describe("horizontal placement", () => {
  it("centres the lanes with a clamped gap", () => {
    const { x, gap } = placeLanes([100, 100, 100], 1400, T);
    expect(gap).toBe(320);
    expect(x[0]! + (x[2]! + 100)).toBe(1400);
    expect(placeLanes([100, 100, 100], 1000, T).gap).toBe(310);
    expect(placeLanes([300, 300, 300], 1000, T).gap).toBe(48);
    expect(placeLanes([10], 100, T).width).toBe(560);
  });
  it("ends the left lane on its right edge and gives a pill the lane's width", () => {
    expect(roleOf(0, 3)).toBe("endL");
    expect(roleOf(1, 3)).toBe("pill");
    expect(roleOf(2, 3)).toBe("endR");
    expect(placeNode(LaneRole.EndL, 100, 200, 120)).toEqual({ left: 180, width: null, portL: null, portR: 304 });
    expect(placeNode(LaneRole.Pill, 100, 200, 120)).toEqual({ left: 100, width: 200, portL: 100, portR: 300 });
    expect(placeNode(LaneRole.EndR, 100, 200, 120)).toEqual({ left: 100, width: null, portL: 96, portR: null });
  });
  it("stands a caption over its lane's text edge, inside the gutters", () => {
    expect(captionX(LaneRole.EndL, 100, 200, 50, 1000, 40)).toBe(250);
    expect(captionX(LaneRole.EndR, 100, 200, 50, 1000, 40)).toBe(100);
    expect(captionX(LaneRole.Pill, 100, 200, 50, 1000, 40)).toBe(175);
    expect(captionX(LaneRole.EndR, 990, 200, 50, 1000, 40)).toBe(910);
  });
  it("draws a horizontal bezier", () => {
    expect(edgePath(0, 10, 100, 30)).toEqual({ d: "M0,10 C50,10 50,30 100,30", mid: [50, 20] });
    expect(edgePath(0, 0, 20, 0).d).toBe("M0,0 C24,0 -4,0 20,0");
  });
});

describe("focus", () => {
  const md = model([pt("a", 0), pt("b", 1), pt("c", 2), pt("d", 1)], [["b", "a"], ["b", "c"], ["a", "d"]], 3, 1, ["b-c"]);
  const es = orient(md);
  it("orients edges by lane", () => {
    expect(es[0]).toMatchObject({ L: "a", R: "b" });
  });
  it("walks the paths through a point both ways", () => {
    const p = pathsThrough(es, "b");
    expect([...p.nodes].sort()).toEqual(["a", "b", "c"]);
    expect([...p.edges].sort()).toEqual([0, 1]);
  });
  it("shows a critical line's words unless the focus dims it, and the words around the hovered point", () => {
    expect(chipEdges(es, null, null)).toEqual([1]);
    expect(chipEdges(es, pathsThrough(es, "d"), null)).toEqual([]);
    expect(chipEdges(es, pathsThrough(es, "d"), "d")).toEqual([2]);
  });
  it("draws edges between ports and collects each port once", () => {
    const ys = new Map([["a", 100], ["b", 100], ["c", 100], ["d", 200]]);
    const placed = new Map([
      ["a", placeNode(LaneRole.EndL, 0, 100, 80)],
      ["b", placeNode(LaneRole.Pill, 200, 100, 80)],
      ["d", placeNode(LaneRole.Pill, 200, 100, 80)],
      ["c", placeNode(LaneRole.EndR, 400, 100, 80)],
    ]);
    const { lines, ports } = drawEdges(es, placed, ys);
    expect(lines).toHaveLength(3);
    expect(lines[0]!.d.startsWith("M104,100")).toBe(true);
    expect(ports.filter((p) => p.id === "a")).toHaveLength(1);
  });
});

describe("the demo's maps", () => {
  const dir = new Directory(DEMO, demoContributions(), { now: DEMO_NOW, places: [] });
  const maps = [
    { kind: MapKind.Access, anchor: "org:acme" },
    { kind: MapKind.Relations, anchor: "item:aws" },
    { kind: MapKind.Relations, anchor: "item:key-prod" },
    { kind: MapKind.Topology, anchor: "plugin:ssh" },
  ];
  for (const m of maps)
    it(`keeps every lane's points a gap apart: ${m.kind} ${m.anchor}`, () => {
      const md = mapModel(dir, m);
      const ys = placeVertical(md, 760, T);
      for (let l = 0; l < md.lanes.length; l++) {
        const v = md.nodes.filter((n) => n.lane === l).map((n) => ys.get(n.id)!).sort((a, b) => a - b);
        for (let i = 1; i < v.length; i++) expect(v[i]! - v[i - 1]!).toBeGreaterThanOrEqual(T.gap);
      }
      const lw = laneWidths(md, new Map(md.nodes.map((n) => [n.id, 180])), md.lanes.map(() => 60));
      const { x } = placeLanes(lw, 1100, T);
      const placed = new Map(md.nodes.map((n) => [n.id, placeNode(roleOf(n.lane, md.lanes.length), x[n.lane]!, lw[n.lane]!, 180)]));
      expect(() => drawEdges(orient(md), placed, ys)).not.toThrow();
    });
});
