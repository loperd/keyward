import { useSyncExternalStore } from "react";

/// What is open in the HashiCorp section.
///
/// The list of connections lives in the section's column and the Vault itself
/// in the main one: different branches of the tree, with no common parent.
/// Their choice cannot be kept in the core — the core knows nothing of
/// connections — so it lies here, in a tiny store of the plugin's own.
function store<T>(initial: T) {
  let value = initial;
  const listeners = new Set<() => void>();
  return {
    set(next: T) {
      if (next === value) return;
      value = next;
      for (const l of listeners) l();
    },
    use(): T {
      return useSyncExternalStore(
        (l) => {
          listeners.add(l);
          return () => {
            listeners.delete(l);
          };
        },
        () => value,
      );
    },
  };
}

const openedStore = store<string | null>(null);
/// The harness opens the connection wizard by a link: `?connect=1`.
const connectingStore = store(new URLSearchParams(window.location.search).has("connect"));

export const useOpened = openedStore.use;
export const setOpened = (id: string | null) => openedStore.set(id);
export const useConnecting = connectingStore.use;
export const setConnecting = (on: boolean) => connectingStore.set(on);

/// "The connections changed": the list in the section's column is re-read
/// when a Vault is connected, edited or forgotten.
let rev = 0;
const revision = store(0);
export const useRevision = revision.use;
export const bumpConnections = () => revision.set((rev += 1));
