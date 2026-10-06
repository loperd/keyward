// A button's own answer to its own action: busy while the action runs (a
// spinner in place of its icon, the button held), then a short "done" (the
// icon turns into a check) where the action finishes without taking the
// person anywhere — a copy, above all. A refusal leaves "done" out: the
// window's report says why.
import { useCallback, useEffect, useRef, useSyncExternalStore } from "react";

export enum Phase {
  Idle = "idle",
  Busy = "busy",
  Done = "done",
}

/// What an action came to: done (the button says so), nothing to say (a
/// prompt given up, a step that moved the line — the new place is the
/// answer), or failed (reported elsewhere).
export enum Outcome {
  Done = "done",
  None = "none",
  Failed = "failed",
}

/// How long a "done" stays on a button.
export const DONE_MS = 1200;

export type Timers = {
  set: (fn: () => void, ms: number) => unknown;
  clear: (id: unknown) => void;
};
const REAL: Timers = { set: (fn, ms) => setTimeout(fn, ms), clear: (id) => clearTimeout(id as ReturnType<typeof setTimeout>) };

/// The phases of one button. A press while busy is refused (the button is
/// held); a press while "done" starts over.
export class Feedback {
  private p: Phase = Phase.Idle;
  private timer: unknown = null;
  private listeners = new Set<() => void>();
  private disposed = false;

  constructor(
    private readonly holdMs: number = DONE_MS,
    private readonly timers: Timers = REAL,
  ) {}

  phase(): Phase {
    return this.p;
  }

  /// Runs the action; false when the button was busy and nothing ran.
  run(action: () => Promise<Outcome>): Promise<boolean> {
    if (this.disposed) throw new Error("a button's feedback ran after it was let go");
    if (this.p === Phase.Busy) return Promise.resolve(false);
    this.stopTimer();
    this.set(Phase.Busy);
    let p: Promise<Outcome>;
    try {
      p = action();
    } catch (e) {
      this.set(Phase.Idle);
      return Promise.reject(e);
    }
    return p.then(
      (o) => {
        this.finish(o);
        return true;
      },
      (e: unknown) => {
        this.finish(Outcome.Failed);
        throw e;
      },
    );
  }

  subscribe(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /// The button is on the screen; the returned function lets it go (a
  /// pending "done" is dropped, a late answer changes nothing).
  attach(): () => void {
    this.disposed = false;
    return () => {
      this.disposed = true;
      this.stopTimer();
      this.p = Phase.Idle;
    };
  }

  dispose() {
    this.disposed = true;
    this.stopTimer();
    this.listeners.clear();
  }

  private finish(o: Outcome) {
    // An answer after the button left the screen changes nothing.
    if (this.disposed) return;
    if (o !== Outcome.Done || this.holdMs <= 0) return this.set(Phase.Idle);
    this.set(Phase.Done);
    this.timer = this.timers.set(() => {
      this.timer = null;
      this.set(Phase.Idle);
    }, this.holdMs);
  }

  private stopTimer() {
    if (this.timer !== null) this.timers.clear(this.timer);
    this.timer = null;
  }

  private set(p: Phase) {
    if (this.p === p) return;
    this.p = p;
    for (const l of this.listeners) l();
  }
}

/// A button's feedback for the life of the component.
/// `report` hears a failure the action did not report itself.
export function useFeedback(report: (e: unknown) => void, holdMs: number = DONE_MS): { phase: Phase; run: (action: () => Promise<Outcome>) => void } {
  const ref = useRef<Feedback | null>(null);
  if (!ref.current) ref.current = new Feedback(holdMs);
  const fb = ref.current;
  useEffect(() => fb.attach(), [fb]);
  const phase = useSyncExternalStore(
    (cb) => fb.subscribe(cb),
    () => fb.phase(),
  );
  const run = useCallback((action: () => Promise<Outcome>) => void fb.run(action).catch(report), [fb, report]);
  return { phase, run };
}
