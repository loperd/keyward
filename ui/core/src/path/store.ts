// Where the window is and how it got there. One store per window: the path
// state, the history of committed lines (back and forward walk it), and the
// column the keyboard is in. Every change goes through `commit`, so the URL,
// the crumbs and the columns can never disagree.
import { useSyncExternalStore } from "react";
import { columns, EMPTY, isFilter, objectOf, rows, isStep, type PathState, type Query, type Segment, type MapRef, CrumbCut } from "./query";
import { MapKind } from "./directory";

export type Snapshot = {
  state: PathState;
  /// The committed line, in syntax: what the URL keeps.
  line: string;
  canBack: boolean;
  canForward: boolean;
  /// The column the keyboard walks: the last one holding a selection, unless
  /// the arrows moved it.
  focus: number;
  /// The column a person unfolded from a spine: the open pair is moved onto
  /// it. A matter of the view only — the path, the crumbs and the document
  /// stay; any new step drops it.
  shown: number | null;
};

type CommitOpts = { replace?: boolean; focus?: number };

export class PathStore {
  private history: string[] = [""];
  private at = 0;
  private snap: Snapshot;
  private readonly listeners = new Set<() => void>();

  constructor(
    private query: Query,
    initial = "",
  ) {
    const state = initial ? query.compile(initial) : EMPTY;
    const line = query.serialize(state);
    this.history = [line];
    this.snap = { state, line, canBack: false, canForward: false, focus: this.defaultFocus(state), shown: null };
  }

  subscribe = (cb: () => void) => {
    this.listeners.add(cb);
    return () => {
      this.listeners.delete(cb);
    };
  };
  get = () => this.snap;
  get q() {
    return this.query;
  }

  private defaultFocus(st: PathState): number {
    const cols = columns(this.query, st.segs, st.map);
    for (let i = cols.length - 1; i >= 0; i--) if (cols[i]!.sel) return i;
    return Math.max(0, cols.length - 1);
  }

  private set(state: PathState, focus: number | undefined) {
    this.snap = {
      state,
      line: this.query.serialize(state),
      canBack: this.at > 0,
      canForward: this.at < this.history.length - 1,
      focus: focus ?? this.defaultFocus(state),
      shown: null,
    };
    for (const l of this.listeners) l();
  }

  /// A new line: compiled, written back canonically, and a step of history
  /// unless `replace` (arrow keys walking a column are not history).
  commit(line: string, opts: CommitOpts = {}) {
    const state = this.query.compile(line);
    const canon = this.query.serialize(state);
    if (opts.replace) this.history[this.at] = canon;
    else if (this.history[this.at] !== canon) {
      this.history = this.history.slice(0, this.at + 1);
      this.history.push(canon);
      this.at++;
    }
    this.set(state, opts.focus);
  }
  commitState(state: PathState, opts: CommitOpts = {}) {
    this.commit(this.query.serialize(state), opts);
  }

  back() {
    this.travel(-1);
  }
  forward() {
    this.travel(1);
  }
  private travel(d: number) {
    const n = this.at + d;
    if (n < 0 || n >= this.history.length) return;
    this.at = n;
    this.set(this.query.compile(this.history[n]!), undefined);
  }

  /// Cut the path back to a crumb: a depth, the map, or the verb.
  cut(to: number | CrumbCut) {
    const s = this.snap.state;
    if (to === CrumbCut.Verb) return this.commitState({ ...s, verb: null, arg: "" });
    if (to === CrumbCut.Map) return this.closeMap();
    this.commitState({ segs: s.segs.slice(0, to), map: null, verb: null, arg: "" });
  }

  /// The segments that lead to a node, and the map kept while the node is on
  /// it.
  private keepMap(segs: Segment[]): PathState {
    const s = this.snap.state;
    const o = objectOf(segs);
    return { segs, map: s.map && this.query.mapHas(s.map, o) ? s.map : null, verb: null, arg: "" };
  }

  /// Choose a row of the column at `depth`: the path is cut there and
  /// continues with the row. A map stays open while the row is on it.
  choose(depth: number, id: string, opts: CommitOpts = {}) {
    this.commitState(this.keepMap([...this.snap.state.segs.slice(0, depth), { id }]), opts);
  }

  /// Go to a node by its home, keeping the map while the node is on it.
  go(id: string) {
    this.commitState(this.keepMap(this.query.dir.node(id).home.map((x) => ({ id: x }))));
  }

  /// Unfold a spine: the open pair moves onto it and the column it leaves
  /// folds, with the width animating. The path is not touched.
  expand(column: number) {
    const n = columns(this.query, this.snap.state.segs, this.snap.state.map).length;
    if (column < 0 || column >= n) throw new Error(`no column ${column} to unfold (there are ${n})`);
    this.snap = { ...this.snap, shown: column, focus: column };
    for (const l of this.listeners) l();
  }

  /// A map of the object, or of the place the object lives in when it is not
  /// one of the map's points.
  openMap(map: MapRef) {
    const s = this.snap.state;
    const o = objectOf(s.segs);
    if (map.kind === MapKind.Relations) {
      const segs = o === map.anchor ? s.segs : this.query.dir.node(map.anchor).home.map((x) => ({ id: x }));
      return this.commitState({ segs, map, verb: null, arg: "" });
    }
    if (o && this.query.mapHas(map, o)) return this.commitState({ segs: s.segs, map, verb: null, arg: "" });
    const row = this.query.dir.all().find((n) => n.map && n.map.kind === map.kind && n.map.anchor === map.anchor);
    if (!row) throw new Error(`no row opens the ${map.kind} map of "${map.anchor}"`);
    this.commitState({ segs: row.home.map((x) => ({ id: x })), map, verb: null, arg: "" });
  }
  /// Close the map: a map that is a row of its own steps back off that row.
  closeMap() {
    const s = this.snap.state;
    if (!s.map) return;
    const o = objectOf(s.segs);
    const segs = o && this.query.dir.node(o).map ? s.segs.slice(0, -1) : s.segs;
    this.commitState({ segs, map: null, verb: null, arg: "" });
  }

  /// A verb over the object.
  verb(id: string | null) {
    const s = this.snap.state;
    this.commitState({ segs: s.segs, map: id === null ? s.map : null, verb: id, arg: "" });
  }

  /// The verb was answered in place (`> edit` turns the document itself into
  /// a form): the line goes back to the path, and the step the verb took is
  /// not left in the history.
  settle() {
    const s = this.snap.state;
    if (s.verb === null) return;
    const line = this.query.serialize({ ...s, verb: null, arg: "" });
    if (this.at > 0 && this.history[this.at - 1] === line) {
      this.history.splice(this.at, 1);
      this.at--;
    } else this.history[this.at] = line;
    this.set(this.query.compile(line), undefined);
  }

  /// The arrows. Up and down walk the focused column; right steps into the
  /// next column (its selection, or its first row); left steps back out.
  /// Walking a column is not history.
  move(d: 1 | -1) {
    const s = this.snap.state;
    const cols = columns(this.query, s.segs, s.map);
    const f = Math.min(this.snap.focus, cols.length - 1);
    const col = cols[f];
    if (!col) return;
    const ids = rows(this.query, col).filter(isStep).map((x) => x.id);
    if (!ids.length) return;
    let i = col.sel ? ids.indexOf(col.sel) : -1;
    i = i < 0 ? 0 : Math.min(ids.length - 1, Math.max(0, i + d));
    this.commitState(this.keepMap([...s.segs.slice(0, col.at), { id: ids[i]! }]), { replace: true, focus: f });
  }
  right() {
    const s = this.snap.state;
    if (s.map) return;
    const cols = columns(this.query, s.segs, s.map);
    const f = this.snap.focus;
    const nx = cols[f + 1];
    if (!cols[f]?.sel || !nx) return;
    const first = rows(this.query, nx).filter(isStep)[0]?.id;
    if (!first) return;
    this.commitState({ segs: [...s.segs.slice(0, nx.at), { id: nx.sel ?? first }], map: null, verb: null, arg: "" }, { replace: true, focus: f + 1 });
  }
  left() {
    const s = this.snap.state;
    const cols = columns(this.query, s.segs, s.map);
    const f = this.snap.focus;
    if (f <= 0) return;
    const col = cols[f]!;
    this.commitState({ segs: s.segs.slice(0, col.at), map: null, verb: null, arg: "" }, { replace: true, focus: f - 1 });
  }
  /// ⌫ outside the line: the verb, then the map, then the last step.
  drop() {
    const s = this.snap.state;
    if (s.verb !== null) return this.verb(null);
    if (s.map) return this.closeMap();
    if (s.segs.length) this.commitState({ segs: s.segs.slice(0, -1), map: null, verb: null, arg: "" });
  }
  /// ⌫ in an empty line: like `drop`, but a filter gives its last piece back
  /// to the line as syntax, to be edited. Returns that piece.
  unwind(): string {
    const s = this.snap.state;
    const l = s.segs[s.segs.length - 1];
    if (s.verb !== null || s.map || !l || !isFilter(l)) {
      this.drop();
      return "";
    }
    const f = { tokens: [...l.filter.tokens], words: [...l.filter.words] };
    let piece: string;
    if (f.words.length) piece = f.words.pop()!;
    else {
      const x = f.tokens.pop()!;
      piece = `${x.k}:${x.v}`;
    }
    const rest = f.tokens.length || f.words.length ? [{ filter: f }] : [];
    this.commitState({ segs: [...s.segs.slice(0, -1), ...rest], map: null, verb: null, arg: "" });
    return piece;
  }

  /// The catalogue changed: the same line is read against the new graph, so
  /// a step that vanished drops out instead of pointing at nothing.
  /// `notify: false` is for a window that rebuilds its graph while drawing:
  /// its parts read the new state as they draw, and nobody is told to draw
  /// again in the middle of it.
  rebase(query: Query, notify = true) {
    this.query = query;
    const state = query.compile(this.snap.line);
    this.history[this.at] = query.serialize(state);
    if (notify) this.set(state, this.snap.focus);
    else this.snap = { ...this.snap, state, line: this.query.serialize(state) };
  }

  object() {
    return objectOf(this.snap.state.segs);
  }
}

export function usePath(store: PathStore): Snapshot {
  return useSyncExternalStore(store.subscribe, store.get);
}
