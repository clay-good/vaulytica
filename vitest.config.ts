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
    // Vitest's default is 5s, and this suite has three kinds of test that
    // cannot promise to finish inside it when the whole suite is running at
    // full parallelism: the ones that SPAWN THE CLI as a subprocess
    // (`cli-stream-contract`), the ones that WALK AND SCAN EVERY SOURCE FILE
    // (`apostrophe-tolerance`, `inert-case-anchor`), and the ones that run
    // every rule in the catalog against a probe document (`title-vacuity`,
    // `boilerplate-satisfaction`). Each of them passes comfortably on its own
    // and each was seen to time out during a loaded run — a false failure that
    // says nothing about the code and costs a re-run to diagnose.
    //
    // A ceiling on a known-slow path, not a budget: a test that genuinely
    // hangs still fails, a minute later. The per-test 120s overrides already in
    // the suite stay where they are.
    //
    // 🚨 **30s → 60s (9.589.0): the same condition recurred, and this time it
    // hid.** `duplicate-logic` (a whole-tree TypeScript parse) and
    // `secondary-family-cap-caveat` (a 312-specimen sweep) each drifted onto
    // the boundary — **~0.9s and ~6s alone, 30.7s and 30s+ inside the loaded
    // suite** — so each failed roughly one run in five. What made it expensive
    // was not the failures but the diagnosis: `npm run verify | tail` reports
    // **`tail`'s** exit code, so a failed gate read as a passing one, and the
    // failures were TIMEOUTS, which say nothing about the code.
    //
    // The number a wall-clock timeout measures under a parallel runner is the
    // test's cost PLUS however long it waited for a CPU.
    //
    // 🚨 And that second term is NOT bounded by this suite. Measured
    // 2026-09-08 while `register-format-invariance` reported **1,542 seconds**
    // for nine tests that take about a minute in total: the machine was also
    // running two OTHER repositories' vitest suites, eight workers each, 42
    // node processes between them. Nothing in this repo had regressed.
    //
    // So "re-measure it alone" means alone on the MACHINE, not merely alone in
    // the suite — `ps -Ao pid,etime,pcpu,args | grep vitest` before believing a
    // timing failure. This will need raising again; the fix each time is to
    // measure, not to guess.
    testTimeout: 60_000,
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
      // Floors (regression-only) — set a couple points under the measured
      // baseline (statements 92.22 · branches 81.06 · functions 92.80 ·
      // lines 93.73, measured 2026-08-17), leaving headroom for cross-platform
      // drift (the gate runs on ubuntu/Node-22 CI). A ratchet raises these as
      // coverage climbs; they only ever fail on a *drop*. Ratcheted here from
      // 85/85/70/83, which were a couple points under the FIRST baseline
      // (2026-06-05) and had been left ~8 points behind ever since — a floor
      // that far under the real number stops being a regression gate.
      // README's coverage table quotes these; mutation-scope.test.ts pins the
      // two together.
      thresholds: {
        lines: 91,
        functions: 90,
        branches: 78,
        statements: 90,
      },
    },
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
});
