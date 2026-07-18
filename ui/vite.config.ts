import { defineConfig } from "vite";

// Port fixed to match src-tauri/tauri.conf.json's `build.devPath`.
export default defineConfig({
  server: {
    port: 1420,
    strictPort: true,
  },
});
