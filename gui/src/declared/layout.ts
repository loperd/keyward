// The window's layout, as a component may ask of it. A drawer asks for the
// section's column to step aside while it is open; the shell listens. No
// plugin reaches into the shell: it declares a drawer, the core does this.
import { useSyncExternalStore } from "react";

const wants = new Set<symbol>();
const listeners = new Set<() => void>();
let collapsed = false;

function emit() {
  const next = wants.size > 0;
  if (next === collapsed) return;
  collapsed = next;
  for (const l of listeners) l();
}

/// Ask for the section's column to be folded; call the result to let go.
export function foldContext(): () => void {
  const me = Symbol("fold");
  wants.add(me);
  emit();
  return () => {
    wants.delete(me);
    emit();
  };
}

export function useContextFolded(): boolean {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => {
        listeners.delete(l);
      };
    },
    () => collapsed,
  );
}
