import { defineConfig } from "vitest/config";

/**
 * Minimal vitest config for Stryker mutation runs (spec-v7 Step 123).
 *
 * Scoped to the unit tests that directly cover the mutated extractors, so a
 * per-mutant test run is tiny and fast (the full 2,600-test suite per mutant
 * would make mutation testing intractable). Node environment — the targeted
 * extractors are pure functions over a DocumentTree, no DOM needed.
 */
export default defineConfig({
  test: {
    include: ["src/extract/dates.test.ts", "src/extract/amounts.test.ts"],
    environment: "node",
    globals: false,
  },
});
