import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  resolve: {
    alias: [
      // The shared core the window is drawn by.
      { find: /^@keyward\/core$/, replacement: resolve(here, "../ui/core/src/index.ts") },
      // Every `invoke` goes through the log of actions: the import is swapped
      // for a wrapper at build time. The bridge itself is left alone: Tauri
      // defines it read-only, and writing over it took the whole window down.
      { find: /^@tauri-apps\/api\/core$/, replacement: resolve(here, "app/ipc.ts") },
      { find: /^@tauri-real\/core$/, replacement: resolve(here, "../node_modules/@tauri-apps/api/core.js") },
    ],
  },
  // The core and its dictionaries live outside `gui`.
  server: { port: 5173, strictPort: true, fs: { allow: [".."] } },
  // One page, the window (app.html), which the Tauri window opens.
  build: {
    target: "safari15",
    emptyOutDir: true,
    rollupOptions: { input: { app: resolve(here, "app.html") } },
  },
});
