import { defineConfig } from "vitest/config";

/**
 * Minimal vitest config for Stryker mutation runs (spec-v7 Step 123).
 *
 * Scoped to the unit tests that directly cover the mutated extractors, so a
 * per-mutant test run is tiny and fast (the full test suite per mutant would
 * make mutation testing intractable). Node environment — the targeted
 * extractors are pure functions over a DocumentTree, no DOM needed.
 *
 * The list must name EVERY test file that imports a mutated module, not just
 * the same-named one. That distinction is not cosmetic: this config listed
 * only `x.test.ts` for each mutated `x.ts`, so the sibling phrasing suites
 * (`date-format-phrasing`, `amount-postfix-currency`, `composite-dollar-currency`)
 * never ran under mutation. Their kills went uncounted and the mutants they
 * cover were reported "NoCoverage" — which is what made `DAY_MONTH_YEAR` and
 * `postfixCurrency` look like entirely untested shipped features in the
 * 2026-08-17 baseline when both had been tested for weeks. An excluded test
 * file understates the score and misdiagnoses the cause.
 *
 * `tests/integration/mutation-scope.test.ts` derives the correct list from the
 * test files' own imports and asserts this one matches, so a new phrasing
 * suite cannot be silently left out.
 */
export default defineConfig({
  test: {
    include: [
      "src/extract/amount-postfix-currency.test.ts",
      "src/extract/amounts.test.ts",
      "src/extract/arbitration-seat-phrasing.test.ts",
      "src/extract/composite-dollar-currency.test.ts",
      "src/extract/crossrefs.test.ts",
      "src/extract/date-format-phrasing.test.ts",
      "src/extract/dates.test.ts",
      "src/extract/govlaw-phrasing.test.ts",
      "src/extract/jurisdictions.test.ts",
      "src/extract/obligations.test.ts",
      "src/extract/parties-hygiene.test.ts",
      "src/extract/parties.test.ts",
      "src/extract/relative-deadline-phrasing.test.ts",
      "src/extract/sections.test.ts",
      "src/extract/venue-phrasing.test.ts",
    ],
    environment: "node",
    globals: false,
  },
});
