import { fileURLToPath } from "node:url";
import { defineConfig, loadEnv, type ProxyOptions } from "vite";
import react from "@vitejs/plugin-react";

const core = fileURLToPath(new URL("../ui/core/src/", import.meta.url));

// The web app: one page, served same-origin behind the Vaultwarden it is
// built for (see README.md). `base: "./"` lets it live under any path.
//
// In development, `VITE_KEYWARD_SERVER=https://vault.example.com npm run dev`
// proxies that server's /api and /identity through the dev server, and the
// page talks to its own origin: same-origin, as it will be when deployed, so
// the server needs no CORS. Without the variable the page talks to its own
// origin with nothing behind it (the sign-in shows, the server is
// unreachable).
export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, fileURLToPath(new URL(".", import.meta.url)), "VITE_");
  const remote = command === "serve" ? env.VITE_KEYWARD_SERVER?.replace(/\/+$/, "") : undefined;
  let proxy: Record<string, ProxyOptions> | undefined;
  if (remote) {
    const target = new URL(remote);
    if (target.protocol !== "https:" && target.protocol !== "http:") throw new Error(`VITE_KEYWARD_SERVER is not an http(s) URL: ${remote}`);
    const through: ProxyOptions = {
      target: target.origin,
      changeOrigin: true,
      secure: true,
      // The server sees its own origin, as it would from a page it serves.
      configure: (p) => p.on("proxyReq", (req) => req.setHeader("origin", target.origin)),
    };
    proxy = { "/api": through, "/identity": through };
  }
  return {
    plugins: [react()],
    base: "./",
    clearScreen: false,
    resolve: {
      alias: [
        { find: /^@keyward\/core$/, replacement: `${core}index.ts` },
        { find: /^@keyward\/core\/(.*)$/, replacement: `${core}$1` },
      ],
    },
    // Proxied, the page's own origin is the server: the build-time variable
    // would send it cross-origin.
    define: { __KEYWARD_PROXIED__: JSON.stringify(!!remote) },
    server: { port: 5191, strictPort: true, fs: { allow: [".."] }, ...(proxy ? { proxy } : {}) },
    preview: { port: 5191, strictPort: true },
    build: {
      target: "es2022",
      emptyOutDir: true,
      // No data: URIs: a strict CSP allows only the page's own files.
      assetsInlineLimit: 0,
    },
  };
});
