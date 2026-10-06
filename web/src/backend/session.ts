// What the session keeps, and the lock on idle.
//
// The session lives in this tab's memory only, nothing of it in any storage:
//   - the access and refresh tokens;
//   - the protected user key and private key, still encrypted (the first
//     with the stretched master key, the second with the user key), and the
//     KDF parameters, so a lock can be undone with the master password;
//   - the email and the display name the server gave;
//   - the second factor's "remember me" token, if one was given.
// A reload, a closed tab or a crash therefore means a whole login again:
// sessionStorage is readable by any script that runs in the origin, and is
// written to disk by some browsers for session restore, so a token or a
// protected key put there outlives the page and is one XSS away. Keys, the
// master password and decrypted values are never anywhere but in memory —
// as non-extractable CryptoKeys where they are keys.
//
// The only thing written to storage at all is the device's identifier, a
// random UUID in localStorage.
import type { Kdf } from "./kdf";

export type StorageLike = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
};

export type Persisted = {
  v: 1;
  email: string;
  name: string | null;
  kdf: Kdf;
  protectedKey: string;
  protectedPrivateKey: string | null;
  accessToken: string;
  refreshToken: string;
};

/// The device's identifier. Not a secret and not a token — Bitwarden's web
/// vault keeps its own the same way — but it must outlive the tab, or every
/// login is a "new device" to the server, with an email about it.
const DEVICE_KEY = "keyward.web.device";

export class SessionStore {
  private session: Persisted | null = null;
  private rememberToken: { email: string; token: string } | null = null;

  constructor(private readonly device: StorageLike) {}

  load(): Persisted | null {
    return this.session;
  }

  save(p: Persisted): void {
    this.session = p;
  }

  clear(): void {
    this.session = null;
  }

  remembered(email: string): string | null {
    const r = this.rememberToken;
    return r !== null && r.email === email ? r.token : null;
  }

  remember(email: string, token: string | null): void {
    this.rememberToken = token === null || token === "" ? null : { email, token };
  }

  deviceId(): string {
    const have = this.device.getItem(DEVICE_KEY);
    if (have !== null && /^[0-9a-f-]{36}$/.test(have)) return have;
    const id = globalThis.crypto.randomUUID();
    this.device.setItem(DEVICE_KEY, id);
    return id;
  }
}

/// A storage that keeps nothing past the page: where the browser refuses
/// localStorage (some private modes), the device id lives as long as the page.
export class MemoryStorage implements StorageLike {
  private readonly m = new Map<string, string>();
  getItem(k: string) {
    return this.m.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.m.set(k, v);
  }
  removeItem(k: string) {
    this.m.delete(k);
  }
}

/// What the idle lock listens to; a browser's `window`/`document`, a fake in
/// tests.
export type IdleEnv = {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(h: unknown): void;
  /// Subscribes to a person's activity; returns the unsubscribe.
  onActivity(fn: () => void): () => void;
  /// Subscribes to the page being hidden (`true`) or shown (`false`).
  onVisibility(fn: (hidden: boolean) => void): () => void;
};

export function browserIdleEnv(): IdleEnv | null {
  const w = globalThis as unknown as Window | undefined;
  const d = globalThis.document;
  if (!w || typeof w.addEventListener !== "function" || !d) return null;
  const ACTIVITY = ["pointerdown", "keydown", "wheel", "touchstart"] as const;
  return {
    now: () => Date.now(),
    setTimeout: (fn, ms) => w.setTimeout(fn, ms),
    clearTimeout: (h) => w.clearTimeout(h as number),
    onActivity(fn) {
      for (const e of ACTIVITY) w.addEventListener(e, fn, { passive: true, capture: true });
      return () => {
        for (const e of ACTIVITY) w.removeEventListener(e, fn, { capture: true });
      };
    },
    onVisibility(fn) {
      const h = () => fn(d.visibilityState === "hidden");
      d.addEventListener("visibilitychange", h);
      return () => d.removeEventListener("visibilitychange", h);
    },
  };
}

/// Locks after `timeoutMs` without activity, and on coming back to a page
/// that was hidden for longer than that: a background tab's timers are
/// throttled, so the timer alone could fire late.
export class IdleLock {
  private timer: unknown = null;
  private hiddenAt: number | null = null;
  private offs: (() => void)[] = [];

  constructor(
    private readonly env: IdleEnv,
    private readonly timeoutMs: number,
    private readonly lock: () => void,
  ) {}

  start(): void {
    this.stop();
    this.offs.push(this.env.onActivity(() => this.arm()));
    this.offs.push(
      this.env.onVisibility((hidden) => {
        if (hidden) {
          this.hiddenAt = this.env.now();
          return;
        }
        const since = this.hiddenAt;
        this.hiddenAt = null;
        if (since !== null && this.env.now() - since > this.timeoutMs) this.fire();
        else this.arm();
      }),
    );
    this.arm();
  }

  stop(): void {
    for (const off of this.offs) off();
    this.offs = [];
    if (this.timer !== null) this.env.clearTimeout(this.timer);
    this.timer = null;
    this.hiddenAt = null;
  }

  private arm(): void {
    if (this.timer !== null) this.env.clearTimeout(this.timer);
    this.timer = this.env.setTimeout(() => this.fire(), this.timeoutMs);
  }

  private fire(): void {
    this.stop();
    this.lock();
  }
}
