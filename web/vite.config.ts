/// <reference types="vitest/config" />
import { defineConfig } from "vite";

// In development sleuth-parallel runs separately (--port 8700); in production it serves web/dist.
// Relative asset paths, so the built page also works opened from a plain file server.
export default defineConfig({
  base: "./",
  server: { proxy: { "/api": "http://127.0.0.1:8700" } },
  test: { environment: "node" },
});
