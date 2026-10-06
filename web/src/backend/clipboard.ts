// The clipboard, cleared behind a copy. The value itself is not kept for the
// wait: only its SHA-256 under a random salt, enough to tell whether the
// clipboard still holds what we put there (and so whether clearing it would
// erase something the person copied since).
//
// A browser lets a page touch the clipboard only while it has the focus, and
// reading it may put a "Paste" prompt in front of the person. So:
//   - the clear is never given up: when it is due and the page is not
//     focused, or the browser refuses the write, it stays pending and is
//     tried again the moment the page gets the focus back (focus,
//     visibilitychange), and the state says so ("stuck") for the window to
//     show "the clipboard still holds a secret";
//   - the clipboard is read (to spare a later copy of the person's own) only
//     where the browser says a read is granted without a prompt; anywhere
//     else it is overwritten with "" unread — a lost later copy is the
//     lesser harm than a password left lying there.
import { ClipboardState } from "@keyward/core/backend";
import { constantTimeEqual, utf8, zero, type Bytes } from "./bytes";
import { randomBytes, sha256 } from "./crypto";
import { fail } from "./errors";

export const CLEAR_AFTER_MS = 30_000;

export type ClipboardLike = {
  writeText(text: string): Promise<void>;
  readText(): Promise<string>;
};

export type Timers = {
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
};

export const realTimers: Timers = {
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (h) => globalThis.clearTimeout(h as ReturnType<typeof setTimeout>),
};

/// Where the page's focus is, as the clipboard needs to know it; a browser's
/// `window`/`document`, a fake in tests.
export type FocusEnv = {
  /// The page has the focus and is visible: the clipboard may be written.
  focused(): boolean;
  /// Subscribes to the page getting the focus back (or becoming visible);
  /// returns the unsubscribe.
  onFocus(fn: () => void): () => void;
  /// Whether `readText` would answer without asking the person — only then
  /// is the clipboard read before it is cleared.
  canReadSilently(): Promise<boolean>;
};

/// What the clipboard holds of ours (ui/core's `ClipboardState`):
///   - `idle`: nothing (never copied, cleared, or replaced by the person);
///   - `waiting`: a copied secret, its clear not yet due;
///   - `stuck`: the clear is due and could not be done yet (the page is not
///     focused, or the browser refused) — the clipboard still holds a
///     secret, and the clear is retried on the next focus.
export type { ClipboardState };

export function browserFocusEnv(): FocusEnv | null {
  const w = globalThis as unknown as Window | undefined;
  const d = globalThis.document;
  if (!w || typeof w.addEventListener !== "function" || !d) return null;
  return {
    focused: () => d.visibilityState === "visible" && d.hasFocus(),
    onFocus(fn) {
      const vis = () => {
        if (d.visibilityState === "visible") fn();
      };
      w.addEventListener("focus", fn);
      d.addEventListener("visibilitychange", vis);
      return () => {
        w.removeEventListener("focus", fn);
        d.removeEventListener("visibilitychange", vis);
      };
    },
    async canReadSilently() {
      // Only Chromium answers this query; elsewhere it throws, and a read
      // there may prompt — so it is not read.
      try {
        const s = await globalThis.navigator.permissions.query({ name: "clipboard-read" as PermissionName });
        // boundary: the browser's own word for a granted permission.
        return s.state === "granted";
      } catch {
        return false;
      }
    },
  };
}

/// Where there is no document (a bare test run): always focused, and a read
/// prompts nobody.
const NO_FOCUS_MODEL: FocusEnv = { focused: () => true, onFocus: () => () => {}, canReadSilently: async () => true };

type Pending = { handle: unknown; salt: Bytes; digest: Bytes; due: boolean };

export class ClipboardGuard {
  private pending: Pending | null = null;
  private current: ClipboardState = ClipboardState.Idle;
  private trying: Promise<void> | null = null;
  private readonly listeners = new Set<(s: ClipboardState) => void>();
  private readonly focus: FocusEnv;

  constructor(
    private readonly clip: () => ClipboardLike | undefined = () => globalThis.navigator?.clipboard,
    private readonly timers: Timers = realTimers,
    private readonly afterMs: number = CLEAR_AFTER_MS,
    focus: FocusEnv | null = browserFocusEnv(),
  ) {
    this.focus = focus ?? NO_FOCUS_MODEL;
    // Lives as long as the guard (the backend's life): a clear left stuck
    // by a lock or a log-out is still retried.
    this.focus.onFocus(() => void this.attempt());
  }

  /// In how many whole seconds a copy is cleared.
  clearsInSeconds(): number {
    return Math.round(this.afterMs / 1000);
  }

  /// Whether this page can clear the clipboard at all: there is one to
  /// write to. What `caps.clipboardClears` says.
  canClear(): boolean {
    return typeof this.clip()?.writeText === "function";
  }

  state(): ClipboardState {
    return this.current;
  }

  /// Every change of `state()`; returns the unsubscribe.
  watch(cb: (s: ClipboardState) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /// Puts the value on the clipboard and arranges for it to go. The caller's
  /// string is the only copy; nothing here outlives this call but a salted
  /// digest.
  async copy(value: string): Promise<void> {
    const clip = this.clip() ?? fail("err.clipboardDenied");
    try {
      await clip.writeText(value);
    } catch {
      fail("err.clipboardDenied");
    }
    this.cancel();
    const salt = randomBytes(32);
    const digest = await sha256(salt, utf8(value));
    const p: Pending = { handle: null, salt, digest, due: false };
    p.handle = this.timers.setTimeout(() => {
      p.due = true;
      void this.attempt();
    }, this.afterMs);
    this.pending = p;
    this.set(ClipboardState.Waiting);
  }

  /// Clears now what a copy left, as the timer would: on lock and on logout
  /// a secret must not wait out its thirty seconds. If it cannot be done
  /// now, it stays pending (`stuck`) and is done on the next focus.
  async flush(): Promise<void> {
    const p = this.pending;
    if (!p) return;
    this.timers.clearTimeout(p.handle);
    p.due = true;
    await this.attempt();
  }

  private cancel() {
    const p = this.pending;
    if (!p) return;
    this.timers.clearTimeout(p.handle);
    zero(p.salt, p.digest);
    this.pending = null;
  }

  /// One try at a due clear; one at a time.
  private attempt(): Promise<void> {
    this.trying ??= this.tryClear().finally(() => {
      this.trying = null;
    });
    return this.trying;
  }

  private async tryClear(): Promise<void> {
    const p = this.pending;
    if (!p || !p.due) return;
    const clip = this.clip();
    if (!clip || !this.focus.focused()) {
      this.set(ClipboardState.Stuck);
      return;
    }
    let still = true;
    if (await this.focus.canReadSilently()) {
      let d: Bytes | null = null;
      try {
        const now = await clip.readText();
        d = await sha256(p.salt, utf8(now));
        still = constantTimeEqual(d, p.digest);
      } catch {
        // Granted, and refused anyway: cleared unread.
        still = true;
      } finally {
        zero(d);
      }
    }
    if (still) {
      try {
        await clip.writeText("");
      } catch {
        // Refused (the focus went in the meantime): still pending, and said.
        if (this.pending === p) this.set(ClipboardState.Stuck);
        return;
      }
    }
    // A copy that came while this one was being cleared is its own.
    if (this.pending !== p) return;
    zero(p.salt, p.digest);
    this.pending = null;
    this.set(ClipboardState.Idle);
  }

  private set(s: ClipboardState): void {
    if (this.current === s) return;
    this.current = s;
    for (const l of this.listeners) l(s);
  }
}
