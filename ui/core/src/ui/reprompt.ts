// The re-prompt: an item marked `reprompt` shows, copies and counts down
// nothing until the master password is checked again — every time, there is
// no grace period. Every way to a value (a copy from the line or a button, a
// reveal, a one-time code) asks `confirm` first; a "reveal all" leaves such
// items out. The password goes from the prompt's field straight to the
// backend's `verifyReprompt` and is never kept here. A backend without that
// call enforces the re-prompt itself (the daemon asks for Touch ID): then
// `confirm` lets the call through and the backend decides.
import { isKey, type Text } from "../i18n";

export type RepromptAsk = { itemId: string; busy: boolean; error: Text | null };

type Verify = (itemId: string, password: string) => Promise<void>;

/// What a refusal says: the backend's own key when it has one (`err.*`), the
/// message framed otherwise.
export function repromptRefusal(e: unknown): Text {
  if (e && typeof e === "object" && "code" in e && typeof e.code === "string" && e.code.startsWith("err.") && isKey(e.code)) return { key: e.code };
  const msg = (e instanceof Error ? e.message : String(e)).trim();
  if (msg.startsWith("err.") && isKey(msg)) return { key: msg };
  return { key: "reprompt.failed", args: { reason: { raw: msg } } };
}

export class Reprompt {
  private ask: RepromptAsk | null = null;
  private resolve: ((ok: boolean) => void) | null = null;
  private guarded: ReadonlySet<string> = new Set();
  private readonly listeners = new Set<() => void>();

  constructor(private readonly verify: Verify | undefined) {}

  /// The items of the catalogue that ask again (their ids only).
  setGuarded(ids: Iterable<string>) {
    this.guarded = new Set(ids);
  }
  /// Whether the item asks for the password again, whoever checks it.
  isGuarded(itemId: string): boolean {
    return this.guarded.has(itemId);
  }
  /// Whether the window must ask before a value of the item may be fetched.
  mustAsk(itemId: string): boolean {
    return this.guarded.has(itemId) && this.verify !== undefined;
  }

  subscribe = (cb: () => void) => {
    this.listeners.add(cb);
    return () => {
      this.listeners.delete(cb);
    };
  };
  get = (): RepromptAsk | null => this.ask;
  private set(ask: RepromptAsk | null) {
    this.ask = ask;
    for (const l of this.listeners) l();
  }

  /// `true` once the value may be fetched; `false` when the person gave up
  /// (or another ask, or a lock, took the prompt's place).
  confirm(itemId: string): Promise<boolean> {
    if (!this.mustAsk(itemId)) return Promise.resolve(true);
    this.settle(false);
    return new Promise<boolean>((resolve) => {
      this.resolve = resolve;
      this.set({ itemId, busy: false, error: null });
    });
  }

  /// Checks the typed password. A refusal stays on the prompt, which stays
  /// open for another try; it never lets the call through.
  async submit(password: string): Promise<void> {
    const ask = this.ask;
    if (!ask) throw new Error("a re-prompt password was sent with no prompt open");
    if (!this.verify) throw new Error("a re-prompt was asked of a backend that cannot check it");
    if (ask.busy) return;
    // The ask being checked, by identity: a prompt given up or replaced
    // meanwhile is not the one this answer is for.
    const checking: RepromptAsk = { ...ask, busy: true, error: null };
    this.set(checking);
    try {
      await this.verify(ask.itemId, password);
    } catch (e) {
      if (this.ask === checking) this.set({ ...ask, busy: false, error: repromptRefusal(e) });
      return;
    }
    if (this.ask === checking) this.settle(true);
  }

  cancel() {
    this.settle(false);
  }

  /// The session closed: an open prompt is given up, nothing of the
  /// catalogue is kept.
  close() {
    this.settle(false);
    this.guarded = new Set();
  }

  private settle(ok: boolean) {
    const r = this.resolve;
    this.resolve = null;
    if (this.ask) this.set(null);
    r?.(ok);
  }
}
