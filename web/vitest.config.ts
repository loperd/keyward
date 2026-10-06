import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Node's own WebCrypto stands in for the browser's: the same subtle API, the
// same non-extractable keys.
export default defineConfig({
  resolve: {
    // The core's enums are values: its modules are read from source, as the
    // build reads them (vite.config.ts).
    alias: [
      { find: /^@keyward\/ui\/(.*)$/, replacement: fileURLToPath(new URL("../ui/core/src/$1", import.meta.url)) },
      { find: /^@keyward\/core\/(.*)$/, replacement: fileURLToPath(new URL("../ui/core/src/$1", import.meta.url)) },
    ],
  },
  test: { environment: "node", include: ["test/**/*.test.ts"] },
});
