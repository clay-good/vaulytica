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
 * suite cannot be silently left out. Its derivation walks the WHOLE repo, not
 * just the mutated modules' directories — a covering suite is a covering suite
 * wherever it lives, and the directory-scoped version of that walk was itself
 * hiding two covering gates in `tests/integration/`.
 *
 * Which raises the case this list could not previously express: a covering
 * suite that should be left out ON PURPOSE. So exclusions are now declared,
 * with a reason, in EXCLUDED_COVERING_SUITES below, and the guard checks
 * `included == derived - excluded`. A suite can still be dropped — it just
 * cannot be dropped silently, which is the whole failure this file has a
 * history of.
 */
/**
 * Covering suites deliberately kept OUT of the per-mutant run, each with the
 * measurement that justifies it. The scope guard reads this list, so an entry
 * here is a decision on the record, not an omission.
 */
export const EXCLUDED_COVERING_SUITES: Record<string, string> = {
  // Both are fast-check gates: every `it` generates 100-200 inputs, and Stryker
  // reruns the covering tests once per mutant. Measured on the seven-extractor
  // scope (2,758 mutants): the run went from ~7 minutes to over 66 minutes
  // WITHOUT FINISHING, and three test-runner children were killed for running
  // out of memory along the way. That is not a slow job, it is an unreliable
  // one — and the score it would eventually print is worth less than a weekly
  // signal that actually lands. Their kills therefore go uncounted, which means
  // the published baseline UNDERSTATES the suite's true fault detection; read
  // it as a floor. Both still run on every push as part of the normal suite.
  "tests/integration/fuzz-boundary.test.ts":
    "fast-check gate: ~10x per-mutant cost, three OOM child restarts, 66min without finishing",
  "tests/integration/property-based.test.ts":
    "fast-check gate: ~10x per-mutant cost, three OOM child restarts, 66min without finishing",
  // A whole-CORPUS relation. It imports `CURRENCY_GLYPHS` from the mutated
  // `src/extract/amounts.ts` — deliberately, so the guard and the extractor
  // cannot drift to two spellings of the same set — and that import is what
  // makes it a covering suite. But its two corpus sweeps analyze all 310
  // specimens twice each: ~14s per run against the ~150ms of a typical
  // extractor unit suite, which over 2,758 mutants is the difference between a
  // seven-minute job and a ten-hour one. Its kills go uncounted, so the
  // published baseline understates fault detection here too; read it as a
  // floor. It runs on every push as part of the normal suite.
  "tests/integration/currency-glyph.test.ts":
    "whole-corpus relation: ~14s per run over 310 specimens x2, ~100x the per-mutant cost of a unit suite",
};

export default defineConfig({
  test: {
    include: [
      // A rule guard that reaches into a mutated extractor: its arbitration-seat
      // cases exercise `src/extract/jurisdictions.ts`, so its kills count.
      "src/engine/rules/exec-employment-guards.test.ts",
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
      // Reaches `src/extract/dates.ts` for the named-anchor date a two-column
      // table flattens to a pipe. Unit-speed (~130ms), so unlike the
      // whole-corpus relations it belongs IN the per-mutant run, and its kills
      // count toward the published score.
      "tests/integration/table-flattened-labels.test.ts",
      "src/extract/venue-phrasing.test.ts",
    ],
    environment: "node",
    globals: false,
  },
});
