import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  test: {
    environment: "happy-dom",
    include: [
      "src/**/*.test.ts",
      "tests/**/*.test.ts",
      "dkb/**/*.test.ts",
      "site/**/*.test.ts",
    ],
    globals: false,
    reporters: "default",
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
});
