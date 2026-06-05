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
      // v5 accuracy harness (build-and-CI-only; never imported by src/).
      "tools/**/*.test.ts",
    ],
    globals: false,
    reporters: "default",
    // spec-v7 Part VIII (Steps 115–116) — code-coverage measurement + gate.
    // Scoped to the shipped browser bundle (`src/`); the build-and-CI-only
    // harnesses (`tools/`, `dkb/build/`) and all test scaffolding are
    // excluded so the number describes production logic, not test plumbing.
    // Thresholds are regression-only floors set *just under* the first
    // measured value (spec-v5 §IX #4 philosophy) — they fail the build on a
    // drop, never block on an aspiration. Raise them as coverage rises.
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/*.test.ts",
        "src/extract/_fixtures.ts",
        "src/engine/_test-fixtures.ts",
        "src/**/*.d.ts",
      ],
      reporter: ["text-summary", "json-summary", "html"],
      // Floors (regression-only) — set a couple points under the first
      // measured baseline (statements 85.53 · branches 72.35 · functions
      // 87.12 · lines 87.52, measured 2026-06-05), leaving headroom for
      // cross-platform drift (the gate runs on ubuntu/Node-22 CI). A ratchet
      // raises these as coverage climbs; they only ever fail on a *drop*.
      thresholds: {
        lines: 85,
        functions: 85,
        branches: 70,
        statements: 83,
      },
    },
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
});
