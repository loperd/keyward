// What the window is waiting for: one counter of the backend calls a person
// set going (a copy, a reveal, a code, a sync, a write, a plugin's action, an
// opened item), so the window can show that something is under way and that
// it ended. The activity bar under the strip and the strip's sync button read
// it; nothing else decides whether a call is in flight.
import { useSyncExternalStore } from "react";

/// A call that is under way, by what it is: the strip's sync button turns
/// for a sync, whatever started it.
export enum Busy {
  Sync = "sync",
  Call = "call",
}

/// Ends a call's span. Calling it twice is a bug in the caller, not a
/// no-op: the count would go wrong for everyone else.
export type End = () => void;

export class Activity {
  private counts: Record<Busy, number> = { [Busy.Sync]: 0, [Busy.Call]: 0 };
  private listeners = new Set<() => void>();
  // Bumped on every change, so a snapshot read by React is a new value only
  // when something changed.
  private turn = 0;

  /// How many calls are in flight, of one kind or of all.
  count(kind?: Busy): number {
    return kind ? this.counts[kind] : this.counts.sync + this.counts.call;
  }

  busy(kind?: Busy): boolean {
    return this.count(kind) > 0;
  }

  /// The change counter: what a subscriber compares.
  version(): number {
    return this.turn;
  }

  begin(kind: Busy = Busy.Call): End {
    this.counts[kind] += 1;
    this.changed();
    let ended = false;
    return () => {
      if (ended) throw new Error(`an activity span of "${kind}" was ended twice`);
      ended = true;
      if (this.counts[kind] <= 0) throw new Error(`the activity count of "${kind}" went below zero`);
      this.counts[kind] -= 1;
      this.changed();
    };
  }

  /// Counts a call while it runs. A call that throws before it gives a
  /// promise is counted and let go at once, and its error passes on.
  track<T>(run: () => Promise<T>, kind: Busy = Busy.Call): Promise<T> {
    const end = this.begin(kind);
    let p: Promise<T>;
    try {
      p = run();
    } catch (e) {
      end();
      throw e;
    }
    return p.finally(end);
  }

  subscribe(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  private changed() {
    this.turn += 1;
    for (const l of this.listeners) l();
  }
}

/// Whether a call (of a kind, or any) is in flight, re-rendering on change.
export function useBusy(activity: Activity, kind?: Busy): boolean {
  return useSyncExternalStore(
    (cb) => activity.subscribe(cb),
    () => activity.busy(kind),
  );
}

/// The backend's calls the window waits on, and what each counts as. The
/// session's own calls (the gate's sign-in and unlock) are the gate's to show.
const TRACKED: Record<string, Busy> = {
  sync: Busy.Sync,
  copy: Busy.Call,
  reveal: Busy.Call,
  totp: Busy.Call,
  item: Busy.Call,
  catalog: Busy.Call,
  contributions: Busy.Call,
  trash: Busy.Call,
  restore: Busy.Call,
  purge: Busy.Call,
  pluginAct: Busy.Call,
  accounts: Busy.Call,
  switchAccount: Busy.Call,
  addAccount: Busy.Call,
  logout: Busy.Call,
  lock: Busy.Call,
  verifyReprompt: Busy.Call,
  setInterface: Busy.Call,
  // Writes (writes.ts): every change of a vault, and a fresh value.
  create: Busy.Call,
  update: Busy.Call,
  generate: Busy.Call,
  verifyPassword: Busy.Call,
  createFolder: Busy.Call,
  renameFolder: Busy.Call,
  deleteFolder: Busy.Call,
  createCollection: Busy.Call,
  renameCollection: Busy.Call,
  deleteCollection: Busy.Call,
  invite: Busy.Call,
  setMember: Busy.Call,
  memberFingerprint: Busy.Call,
  confirmMember: Busy.Call,
  removeMember: Busy.Call,
};

/// The same object, its tracked calls counted while they run. A method the
/// object does not have stays absent (the window asks `if (b.pluginAct)`),
/// every other member reads through, and methods keep their `this`.
export function tracked<T extends object>(target: T, activity: Activity): T {
  // One wrapper per method, made anew if the method itself is replaced.
  const wrapped = new Map<PropertyKey, { of: unknown; w: unknown }>();
  return new Proxy(target, {
    get(t, prop, receiver) {
      const v: unknown = Reflect.get(t, prop, receiver);
      if (typeof v !== "function") return v;
      const hit = wrapped.get(prop);
      if (hit && hit.of === v) return hit.w;
      const kind = typeof prop === "string" ? TRACKED[prop] : undefined;
      const fn = v as (...args: unknown[]) => unknown;
      const w = kind
        ? (...args: unknown[]) =>
            activity.track(() => {
              const r = fn.apply(t, args);
              if (!(r instanceof Promise)) throw new Error(`the tracked call "${String(prop)}" gave no promise`);
              return r;
            }, kind)
        : (...args: unknown[]) => fn.apply(t, args);
      wrapped.set(prop, { of: v, w });
      return w;
    },
  });
}
