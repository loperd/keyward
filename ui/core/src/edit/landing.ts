// Where the window steps once a write is answered: a new item or folder, or
// an edited item whose name (and so its slug) may have changed. The line is
// set again only from a graph read after the write, and only once that graph
// has the node. Pure.
import type { Directory } from "../path/directory";
import type { PathStore } from "../path/store";

/// The node to step onto, and the graph it was asked under.
export type Landing = { id: string; after: Directory };

export const landingReady = (l: Landing | null, dir: Directory): l is Landing => !!l && l.after !== dir && dir.has(l.id);

/// Steps onto the landing if the graph is ready for it; whether it did.
export function land(l: Landing | null, dir: Directory, store: PathStore): boolean {
  if (!landingReady(l, dir)) return false;
  store.go(l.id);
  return true;
}
