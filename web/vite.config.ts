import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Node globals without pulling in @types/node for one variable.
declare const process: { env: Record<string, string | undefined> };

// Dev-server API target, e.g. STACKURITY_DEV_BACKEND=http://127.0.0.1:18081 npm run dev
const backend = process.env.STACKURITY_DEV_BACKEND || "http://127.0.0.1:18080";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Not "assets": that would collide with the SPA route /assets (the Go UI
    // handler would serve a directory listing on reload). See ui.go.
    assetsDir: "static",
    sourcemap: false,
    // The backend CSP forbids inline scripts; keep everything in files.
    modulePreload: { polyfill: false },
  },
  server: {
    proxy: {
      "/api": { target: backend, changeOrigin: false },
      "/healthz": { target: backend },
    },
  },
});
