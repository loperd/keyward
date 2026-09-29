import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const here = dirname(fileURLToPath(import.meta.url));
const pluginsDir = resolve(here, "../crates/plugins");

/// A plugin's screens live with the plugin — `crates/plugins/<id>/ui` — and are
/// reached as `@plugin/<id>/…`. The list is read from the directory rather than
/// written out here: the core does not keep a register of plugin names, and a
/// new plugin needs no change to the window's build.
const pluginAliases = readdirSync(pluginsDir, { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => ({ find: `@plugin/${e.name}`, replacement: resolve(pluginsDir, e.name) }));

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  resolve: {
    alias: [
      // What the window lends a plugin's screens: the interface's bricks, the
      // dictionary, the types, the way to call the plugin.
      { find: "@keyward", replacement: resolve(here, "src") },
      // Every `invoke` — the window's and the plugins' screens' — goes through
      // the log of actions: the import is swapped for a wrapper at build time.
      // The bridge itself is left alone: Tauri defines it read-only, and
      // writing over it took the whole window down.
      { find: /^@tauri-apps\/api\/core$/, replacement: resolve(here, "src/ipc.ts") },
      { find: /^@tauri-real\/core$/, replacement: resolve(here, "../node_modules/@tauri-apps/api/core.js") },
      ...pluginAliases,
    ],
  },
  // The dictionaries and the plugins' screens live outside `gui`: the daemon
  // reads the same words, and a plugin's parts belong with the plugin.
  server: { port: 5173, strictPort: true, fs: { allow: [".."] } },
  build: { target: "safari15", emptyOutDir: true },
});
