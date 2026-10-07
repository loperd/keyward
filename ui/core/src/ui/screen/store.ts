// What is open of a plugin's declared screens, node by node: the screen a
// place opened in its page's stead (its route), and the drawer and the
// dialogue over it. A screen left and come back to opens where it was; a
// drawer or a dialogue belongs to the page it opened over and goes when the
// window steps elsewhere. Everything goes when the session closes: a screen
// may show what a plugin found with the vault's keys.
import type { ScreenPage } from "../../plugin/screen";

export type ScreenView = {
  plugin: string;
  /// The screen drawn in the page's stead; `null`: the page stands, and a
  /// drawer or a dialogue may stand over it (a verb's answer).
  route: string | null;
  drawer: ScreenPage | null;
  dialog: ScreenPage | null;
  /// Moves on every `refresh` a reply asks for: whatever the screen loaded
  /// (the page, a tab's body) is asked again.
  epoch: number;
};

export class ScreenStore {
  private views = new Map<string, ScreenView>();
  private listeners = new Set<() => void>();

  /// What is open over a node; `null` for nothing. The same object until it
  /// changes.
  get(node: string): ScreenView | null {
    return this.views.get(node) ?? null;
  }

  subscribe(l: () => void): () => void {
    this.listeners.add(l);
    return () => {
      this.listeners.delete(l);
    };
  }

  /// Changes what is open over a node; a view left with nothing open goes.
  patch(node: string, plugin: string, patch: Partial<Omit<ScreenView, "plugin">>): void {
    const was = this.views.get(node);
    if (was && was.plugin !== plugin) throw new Error(`the node "${node}" holds a screen of "${was.plugin}", not of "${plugin}"`);
    const next: ScreenView = { plugin, route: null, drawer: null, dialog: null, epoch: 0, ...was, ...patch };
    if (next.route === null && !next.drawer && !next.dialog) this.views.delete(node);
    else this.views.set(node, next);
    this.emit();
  }

  /// Opens a screen over a node, or the same one again where it was.
  open(node: string, plugin: string, route: string): void {
    const was = this.views.get(node);
    if (was && was.route === route) return;
    this.patch(node, plugin, { route, drawer: null });
  }

  /// Asks again whatever is drawn over a node.
  refresh(node: string): void {
    const was = this.views.get(node);
    if (was) this.patch(node, was.plugin, { epoch: was.epoch + 1 });
  }

  /// Closes what stands topmost over a node: the dialogue, then the drawer,
  /// then the screen. False when nothing was open.
  closeTop(node: string): boolean {
    const v = this.views.get(node);
    if (!v) return false;
    if (v.dialog) this.patch(node, v.plugin, { dialog: null });
    else if (v.drawer) this.patch(node, v.plugin, { drawer: null });
    else this.patch(node, v.plugin, { route: null });
    return true;
  }

  /// The window stands on `node` now: the drawers and dialogues over other
  /// nodes go; their screens stay, to be come back to.
  only(node: string | null): void {
    let changed = false;
    for (const [id, v] of [...this.views]) {
      if (id === node || (!v.drawer && !v.dialog)) continue;
      changed = true;
      if (v.route === null) this.views.delete(id);
      else this.views.set(id, { ...v, drawer: null, dialog: null });
    }
    if (changed) this.emit();
  }

  /// Forgets everything (the session closed).
  clear(): void {
    if (!this.views.size) return;
    this.views.clear();
    this.emit();
  }

  private emit() {
    for (const l of this.listeners) l();
  }
}
