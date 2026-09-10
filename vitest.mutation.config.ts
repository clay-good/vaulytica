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
  // Both cover `src/report/exports.ts` — deliberately, since each renders every
  // artifact — and both run the FULL analyze pipeline to do it. Measured
  // 2026-09-08: 2.17s and 2.80s against the 386ms of `exports.test.ts`, which
  // over ~790 mutants is the difference between a job that finishes and one
  // nobody waits for. Same call as the three above, and the same caveat: their
  // kills go uncounted, so the published number is a FLOOR. Both run on every
  // push as part of the normal suite.
  "tests/golden/artifact-digests.test.ts":
    "renders every artifact through the full analyze pipeline: 2.17s per run, ~6x a unit suite",
  "tests/integration/report-reproducibility.test.ts":
    "renders every artifact TWICE through the full analyze pipeline: 2.80s per run, ~7x a unit suite",
};

export default defineConfig({
  test: {
    include: [
      // A rule guard that reaches into a mutated extractor: its arbitration-seat
      // cases exercise `src/extract/jurisdictions.ts`, so its kills count.
      "src/engine/rules/exec-employment-guards.test.ts",
      // The pre-disclosure scanner's own suite. It joined the mutated set in
      // 9.552.0 because two of its tests were found passing with the scanner
      // stubbed to return nothing — the class mutation testing exists to find,
      // caught by hand first.
      // Covers both delivery modules: `delivery.test.ts` is the suite for the
      // scanner AND the masking helpers (its "masking helpers" describe block).
      "src/delivery/delivery.test.ts",
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
      // Covers `src/report/exports.ts`, which joined the mutated set in
      // 9.590.0 after four releases took it 46.08% -> 58.53%.
      "src/report/closing-checklist.test.ts",
      "src/report/exports.test.ts",
      "src/report/negotiation-export.test.ts",
      "tests/integration/artifact-prose-sanity.test.ts",
      "tests/integration/citation-completeness.test.ts",
      // Drives `collectDeadlines` over the corpus for the named-anchor
      // resolution that put the Effective Date in the calendar — and, more
      // importantly, for the case-exact test that keeps "the effective date of
      // termination" OUT of it. Both numbers are pinned by equality, so a
      // mutant that relaxes either is killed.
      "tests/integration/named-anchor-resolution.test.ts",
      // Imports `critical-dates.ts` for its register TYPE while testing the
      // export Blob wrappers. A type-only import is still an import as far as
      // the scope guard is concerned, and including it costs nothing: the suite
      // is 11 fast unit tests.
      "src/report/export-blobs.test.ts",
      // The critical-dates register's three suites. It joined the mutated set
      // in 9.568.0: the arithmetic behind every date an attorney acts on.
      "src/report/critical-dates-kind.test.ts",
      "src/report/critical-dates-responsible.test.ts",
      "src/report/critical-dates.test.ts",
      "src/extract/sections.test.ts",
      // Reaches `src/extract/dates.ts` for the named-anchor date a two-column
      // table flattens to a pipe. Unit-speed (~130ms), so unlike the
      // whole-corpus relations it belongs IN the per-mutant run, and its kills
      // count toward the published score.
      "tests/integration/table-flattened-labels.test.ts",
      "src/extract/venue-phrasing.test.ts",
      // The privilege-log parser's two suites. It joined the mutated set in
      // 9.613.0 at 60.53%, above the aggregate — a CSV written by opposing
      // counsel, where a cell that fails to split drops the entry out of every
      // Bates range check silently.
      "src/production/privilege-log.test.ts",
      "src/production/reconcile.test.ts",
    ],
    environment: "node",
    globals: false,
  },
});
