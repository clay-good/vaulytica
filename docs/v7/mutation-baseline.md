# Mutation-testing baseline (spec-v7 Steps 123–124)

> Committed honestly, like the [coverage baseline](../../README.md#build--verify) and the [v5 accuracy scoreboard](../v5/methodology.md): a *measured number*, not a target. Re-measure with `npm run mutation`; the HTML report lands in `reports/mutation/` (gitignored).

## Why mutation testing

Code coverage says a line *ran*; it does not say a test would *catch a bug* on that line. A suite can have 90% coverage and still pass when a `>` is silently changed to `>=`. Mutation testing measures the suite's **fault-detection power**: Stryker injects small faults ("mutants") into the source, runs the covering tests, and reports how many mutants the tests *killed*. A surviving mutant is a behavior the tests do not pin — a real weak spot (equivalent mutants aside).

## Scope

Scoped first to the **highest-value pure logic** the spec named: the date and amount extractors (`src/extract/dates.ts`, `src/extract/amounts.ts`). These are dense regex/decimal/branch logic that the highest-value temporal and financial rules depend on. The scope has since widened to four extractors — `crossrefs.ts` and `sections.ts` joined on 2026-08-17; the engine core (`src/engine/`) is the next target.

Stryker runs the test suite once per mutant, so it is **slow** and runs **off the per-push path** — a weekly schedule + on-demand (`.github/workflows/mutation.yml`), never the `ci.yml` gate. Per-mutant runs use a minimal vitest config (`vitest.mutation.config.ts`) that includes only the covering unit-test files, so a run completes in a few minutes. That `include` list and `mutate` in `stryker.config.json` are two hand-maintained lists naming the same modules: a file added to `mutate` alone reports 0% with every mutant "NoCoverage" (its tests exist but never run), so `tests/integration/mutation-scope.test.ts` asserts they agree.

## Baseline (2026-08-17, four-extractor scope)

| File | Mutation score | Killed | Survived | Timeout | No coverage |
|---|---:|---:|---:|---:|---:|
| **All (scoped)** | **53.94%** | 757 | 621 | 16 | 39 |
| `amounts.ts` | 61.16% | 215 | 136 | 7 | 5 |
| `dates.ts` | 56.58% | 266 | 194 | 9 | 17 |
| `sections.ts` | 51.92% | 27 | 21 | 0 | 4 |
| `crossrefs.ts` | 46.80% | 249 | 270 | 0 | 13 |

(Mutation score = killed ÷ (killed + survived + timeout + no-coverage). The "covered" score, excluding no-coverage mutants, is 55.45% overall.)

**Read the aggregate against its scope, never across scopes.** 53.94% is *lower* than the 56.16% recorded for the two-file scope, and that is not a regression: the surface grew from 846 mutants to 1,433, and the two files that joined score below the original pair.

### History

| Date | Scope | Score | Break | Note |
|---|---|---:|---:|---|
| 2026-06-05 | dates + amounts | 51.26% → 55.65% | 48 | First run, then a survivor-fix pass (unit→day conversion, `before`-direction signing, scale-suffix multiplication, range-currency inheritance). |
| 2026-08-17 | dates + amounts | **47.59%** | 48 | **Gate broke.** Not a flake — real decay. Both files had grown (postfix currencies, fiscal quarters, composite `$`, new date anchors) without matching tests, so 112 mutants had no coverage at all. |
| 2026-08-17 | dates + amounts | 56.16% | 54 | Three entirely untested shipped features covered: `postfixCurrency` (trailing currency words), `DAY_MONTH_YEAR` (day-before-month dates), `CURRENCY_OVERRIDE` (the v7 §6 deferred override). Each was deletable with the suite green. |
| 2026-08-17 | + crossrefs + sections | 52.34% | 50 | Scope widened; see the note above on comparing scores across scopes. |
| 2026-08-17 | + crossrefs + sections | **53.94%** | 52 | Pinned each external-citation branch in crossrefs (41 rows: every instrument noun, named regime, reporter form, and singular/plural + `§`/`§§` variant). crossrefs 42.86% → 46.80%. |

The lesson the decay taught: a mutation score is not a one-time measurement. Adding code to a mutated file without adding tests lowers it mechanically, and because the job is weekly and off the push path, the failure sits unseen unless someone looks for it. The remaining survivors are the ratchet target, but crossrefs shows where that runs out: 41 new rows pinning every external-citation branch moved it only 42.86% → 46.80%, because most of its ~270 survivors are equivalent mutants inside long alternations (`\s+` → `\s`, `[A-Za-z]+` → `[A-Za-z]`, dropped `^` anchors) that no realistic legal drafting distinguishes. The practical ceiling is well below 100%, and further gains need a different lever — a narrower, more testable decomposition of those regexes — not more test rows.

## Gate (regression-only, Step 124)

`stryker.config.json` sets `thresholds.break = 52` — a couple points under the measured 53.94%, with headroom for cross-platform drift. The scheduled job fails if the score drops below the floor; it never blocks on an unmet aspiration. **Ratchet up as survivors are killed** — the same measure-first discipline coverage and the v5 scoreboard use. The break threshold applies only in the mutation workflow, not the per-push gate.
