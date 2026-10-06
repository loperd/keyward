import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The stand serves the core straight from its sources: the workspace links
// `@keyward/core` to ui/core, which lives outside this folder.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 5190, strictPort: true, fs: { allow: ["../.."] } },
});
