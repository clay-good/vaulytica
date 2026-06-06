# Mutation-testing baseline (spec-v7 Steps 123–124)

> Committed honestly, like the [coverage baseline](../../README.md#build--verify) and the [v5 accuracy scoreboard](../v5/methodology.md): a *measured number*, not a target. Re-measure with `npm run mutation`; the HTML report lands in `reports/mutation/` (gitignored).

## Why mutation testing

Code coverage says a line *ran*; it does not say a test would *catch a bug* on that line. A suite can have 90% coverage and still pass when a `>` is silently changed to `>=`. Mutation testing measures the suite's **fault-detection power**: Stryker injects small faults ("mutants") into the source, runs the covering tests, and reports how many mutants the tests *killed*. A surviving mutant is a behavior the tests do not pin — a real weak spot (equivalent mutants aside).

## Scope

Scoped first to the **highest-value pure logic** the spec named: the date and amount extractors (`src/extract/dates.ts`, `src/extract/amounts.ts`). These are dense regex/decimal/branch logic that the highest-value temporal and financial rules depend on. The scope expands as the score is established; the engine core (`src/engine/`) is the next target.

Stryker runs the test suite once per mutant, so it is **slow** and runs **off the per-push path** — a weekly schedule + on-demand (`.github/workflows/mutation.yml`), never the `ci.yml` gate. Per-mutant runs use a minimal vitest config (`vitest.mutation.config.ts`) that includes only the two covering unit-test files, so a run completes in ~3–4 minutes.

## Baseline (2026-06-05, `@stryker-mutator/core` 9.6.1, after the first survivor-fix pass)

| File | Mutation score | Killed | Survived | Timeout | No coverage |
|---|---:|---:|---:|---:|---:|
| **All (scoped)** | **55.65%** | 322 | 240 | 8 | 23 |
| `dates.ts` | 60.61% | 197 | 113 | 3 | 17 |
| `amounts.ts` | 49.43% | 125 | 127 | 5 | 6 |

(Mutation score = killed ÷ (killed + survived + timeout + no-coverage). The "covered" score, excluding no-coverage mutants, is 57.89% overall.)

The **first** run measured 51.26%; a targeted survivor-fix pass — pinning unit→day conversion and `before`-direction signing in dates, scale-suffix multiplication and range-currency inheritance in amounts — raised it to **55.65%** and demonstrates the measure→fix→re-measure loop the spec calls for. The remaining survivors are the ratchet target; many of the regex survivors (`\s+` → `\s`, character-class tweaks) are equivalent or near-equivalent mutants that no input in the linter's domain distinguishes, so the practical ceiling is below 100%.

## Gate (regression-only, Step 124)

`stryker.config.json` sets `thresholds.break = 48` — a couple points under the measured 55.65%, with headroom for cross-platform drift. The scheduled job fails if the score drops below the floor; it never blocks on an unmet aspiration. **Ratchet up as survivors are killed** — the same measure-first discipline coverage and the v5 scoreboard use. The break threshold applies only in the mutation workflow, not the per-push gate.
