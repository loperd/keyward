// The window's toasts: a word that something happened — done, refused,
// copied — that comes up from the bottom, stays a moment and goes by itself.
// One store per window; the toaster draws it.
import { useSyncExternalStore } from "react";

export enum ToastKind {
  Ok = "ok",
  Error = "error",
  Copy = "copy",
  Info = "info",
}
export type Toast = { id: number; kind: ToastKind; text: string; leaving: boolean };

/// How long a toast stays, by kind: a refusal is read, a "done" glanced at.
export const TOAST_MS: Record<ToastKind, number> = { [ToastKind.Ok]: 3000, [ToastKind.Copy]: 3000, [ToastKind.Info]: 4000, [ToastKind.Error]: 6000 };
/// The most toasts on the screen at once; an older one makes room.
export const TOAST_MAX = 3;

export type ToastTimers = {
  set: (fn: () => void, ms: number) => unknown;
  clear: (id: unknown) => void;
};
const REAL: ToastTimers = { set: (fn, ms) => setTimeout(fn, ms), clear: (id) => clearTimeout(id as ReturnType<typeof setTimeout>) };

export class Toasts {
  private list: readonly Toast[] = [];
  private next = 1;
  private timers = new Map<number, unknown>();
  private listeners = new Set<() => void>();

  constructor(private readonly clock: ToastTimers = REAL) {}

  all(): readonly Toast[] {
    return this.list;
  }

  /// Shows a toast; the same words of the same kind already up are shown
  /// once, their time started again.
  push(kind: ToastKind, text: string): number {
    if (!text) throw new Error("a toast with no words");
    const same = this.list.find((x) => x.kind === kind && x.text === text && !x.leaving);
    if (same) {
      this.arm(same.id, TOAST_MS[kind]);
      return same.id;
    }
    const id = this.next++;
    this.list = [...this.list, { id, kind, text, leaving: false }];
    const shown = this.list.filter((x) => !x.leaving);
    if (shown.length > TOAST_MAX) this.dismiss(shown[0]!.id);
    this.arm(id, TOAST_MS[kind]);
    this.changed();
    return id;
  }

  /// Starts a toast's way out; the toaster calls `remove` when its exit
  /// has played.
  dismiss(id: number) {
    const t = this.list.find((x) => x.id === id);
    if (!t || t.leaving) return;
    this.disarm(id);
    this.list = this.list.map((x) => (x.id === id ? { ...x, leaving: true } : x));
    this.changed();
  }

  remove(id: number) {
    if (!this.list.some((x) => x.id === id)) return;
    this.disarm(id);
    this.list = this.list.filter((x) => x.id !== id);
    this.changed();
  }

  /// Everything goes at once (the window is let go).
  clear() {
    for (const id of this.timers.keys()) this.disarm(id);
    if (!this.list.length) return;
    this.list = [];
    this.changed();
  }

  subscribe(cb: () => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  private arm(id: number, ms: number) {
    this.disarm(id);
    this.timers.set(
      id,
      this.clock.set(() => {
        this.timers.delete(id);
        this.dismiss(id);
      }, ms),
    );
  }

  private disarm(id: number) {
    const h = this.timers.get(id);
    if (h !== undefined) this.clock.clear(h);
    this.timers.delete(id);
  }

  private changed() {
    for (const l of this.listeners) l();
  }
}

export function useToasts(toasts: Toasts): readonly Toast[] {
  return useSyncExternalStore(
    (cb) => toasts.subscribe(cb),
    () => toasts.all(),
  );
}
