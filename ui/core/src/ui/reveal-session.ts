// One secret field's shown value, kept honest against slow answers. Every
// ask carries a token; hiding (on blur, on the page going hidden, on the
// timeout, on another ask, on the field moving to another secret) moves the
// token on, so an answer that arrives after it is dropped at once and never
// shown — a value of item A can never appear in the field of item B. An
// answer that arrives while the window has no focus is dropped too.
import type { Revealed } from "../backend";

export class RevealSession {
  private token = 0;
  private drop: (() => void) | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private disposed = false;

  constructor(
    private readonly onValue: (v: string | null) => void,
    /// Whether the window has the focus (`document.hasFocus()`).
    private readonly focused: () => boolean,
    private readonly ms: number,
  ) {}

  /// Asks `confirm` (the re-prompt), then `fetch`; `true` when the value is
  /// on the screen. A refusal of either rejects; a stale answer is dropped
  /// and resolves `false`.
  async show(fetch: () => Promise<Revealed>, confirm: () => Promise<boolean>): Promise<boolean> {
    if (this.disposed) throw new Error("a secret field was asked to show after it was gone");
    this.hide();
    const n = this.token;
    if (!(await confirm())) return false;
    if (n !== this.token || this.disposed) return false;
    const r = await fetch();
    if (n !== this.token || this.disposed || !this.focused()) {
      r.drop();
      return false;
    }
    this.drop = r.drop;
    this.onValue(r.value);
    this.timer = setTimeout(() => this.hide(), this.ms);
    return true;
  }

  hide() {
    this.token++;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const d = this.drop;
    this.drop = null;
    d?.();
    if (!this.disposed) this.onValue(null);
  }

  /// The field is gone or holds another secret now: nothing it asked for
  /// may show any more.
  dispose() {
    this.hide();
    this.disposed = true;
  }
}

/// A refusal because the vault locked meanwhile: the gate is about to stand,
/// there is nothing to say about it.
export function isLockedError(e: unknown): boolean {
  if (e && typeof e === "object" && "code" in e && e.code === "err.locked") return true;
  return e instanceof Error && e.message.trim() === "err.locked";
}
