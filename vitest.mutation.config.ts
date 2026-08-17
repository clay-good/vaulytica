import { defineConfig } from "vitest/config";

/**
 * Minimal vitest config for Stryker mutation runs (spec-v7 Step 123).
 *
 * Scoped to the unit tests that directly cover the mutated extractors, so a
 * per-mutant test run is tiny and fast (the full 2,600-test suite per mutant
 * would make mutation testing intractable). Node environment — the targeted
 * extractors are pure functions over a DocumentTree, no DOM needed.
 *
 * This list MUST be kept in step with `mutate` in stryker.config.json. A file
 * added to `mutate` whose tests are not included here reports 0% with every
 * mutant "NoCoverage" — the tests exist, they simply never run — which drags
 * the aggregate down and looks like a coverage collapse rather than a config
 * mismatch. `mutation-scope.test.ts` asserts the two lists agree.
 */
export default defineConfig({
  test: {
    include: [
      "src/extract/dates.test.ts",
      "src/extract/amounts.test.ts",
      "src/extract/crossrefs.test.ts",
      "src/extract/sections.test.ts",
    ],
    environment: "node",
    globals: false,
  },
});
