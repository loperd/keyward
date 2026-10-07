/// `@tauri-apps/api/core`, with `invoke` passing through the log of actions.
/// Vite puts this module in place of the real one for every import of it;
/// everything else is the real module's.
export * from "@tauri-real/core";
import { invoke as realInvoke, type InvokeArgs, type InvokeOptions } from "@tauri-real/core";
import { logged } from "./actionLog";

export function invoke<T>(cmd: string, args?: InvokeArgs, options?: InvokeOptions): Promise<T> {
  return logged(cmd, () => realInvoke<T>(cmd, args, options));
}
