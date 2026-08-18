# Mutation-testing baseline (spec-v7 Steps 123–124)

> Committed honestly, like the [coverage baseline](../../README.md#build--verify) and the [v5 accuracy scoreboard](../v5/methodology.md): a *measured number*, not a target. Re-measure with `npm run mutation`; the HTML report lands in `reports/mutation/` (gitignored).

## Why mutation testing

Code coverage says a line *ran*; it does not say a test would *catch a bug* on that line. A suite can have 90% coverage and still pass when a `>` is silently changed to `>=`. Mutation testing measures the suite's **fault-detection power**: Stryker injects small faults ("mutants") into the source, runs the covering tests, and reports how many mutants the tests *killed*. A surviving mutant is a behavior the tests do not pin — a real weak spot (equivalent mutants aside).

## Scope

Scoped to the **highest-value pure logic**: seven extractors under `src/extract/` — `amounts`, `crossrefs`, `dates`, `jurisdictions`, `obligations`, `parties`, `sections`. These are dense regex/decimal/branch logic that the highest-value temporal, financial, jurisdictional, and obligation rules depend on. The engine core (`src/engine/`) is the next target.

Stryker runs the test suite once per mutant, so it is **slow** and runs **off the per-push path** — a weekly schedule + on-demand (`.github/workflows/mutation.yml`), never the `ci.yml` gate. Per-mutant runs use a minimal vitest config (`vitest.mutation.config.ts`) that includes only the covering unit-test files, so a run completes in tens of minutes rather than hours.

### The include list is per-module, not per-filename

`mutate` in `stryker.config.json` and `include` in `vitest.mutation.config.ts` must describe the **same surface**, and the include list must name **every test file that imports a mutated module** — not just the same-named one. Several modules here are covered by sibling suites whose names do not match their module (`date-format-phrasing.test.ts`, `amount-postfix-currency.test.ts`, `composite-dollar-currency.test.ts`, `arbitration-seat-phrasing.test.ts`, `govlaw-phrasing.test.ts`, `venue-phrasing.test.ts`, `parties-hygiene.test.ts`, `relative-deadline-phrasing.test.ts`).

For most of this file's history the list named only `x.test.ts` per mutated `x.ts`, so those suites **never ran under mutation**. Their kills went uncounted and the mutants they cover were reported "NoCoverage" — which is why the 2026-08-17 entry below records `DAY_MONTH_YEAR` and `postfixCurrency` as "entirely untested shipped features" when both had in fact been tested for weeks (`date-format-phrasing.test.ts` dates from 2026-07-25). **An excluded test file both understates the score and misdiagnoses its cause.** Correcting the list lifted `amounts.ts` 61.16% → 64.74% and `dates.ts` 56.58% → 60.91% with no new tests written; `crossrefs.ts`, which had no excluded suite, did not move at all.

`tests/integration/mutation-scope.test.ts` now **derives** the expected include list from the test files' own import statements and asserts the config matches, so a new phrasing suite cannot be silently left out.

### …and the derivation had the same blind spot one level up

That guard scanned only the mutated modules' **own directories**, so a covering suite living anywhere else was invisible to it — it reported agreement while the measurement was still short. Two were hiding there: `tests/integration/fuzz-boundary.test.ts` (which imports four of the seven mutated modules, and is the gate `obligations.ts` cites for its ReDoS property) and `tests/integration/property-based.test.ts` (four). The walk now covers every test file in the repo.

Including them, however, is not free, and the measurement is worth recording. Both are `fast-check` gates: each `it` generates 100–200 inputs, and Stryker reruns the covering tests once per mutant. On the seven-extractor scope (2,758 mutants) the run went from **~7 minutes to over 66 minutes without finishing**, and three test-runner children were killed for **running out of memory** on the way. That is not a slow job but an unreliable one, and a weekly signal that never lands is worth less than one that does.

So they are **declared exclusions**, in `EXCLUDED_COVERING_SUITES` in `vitest.mutation.config.ts`, each carrying the measurement above as its reason; the scope guard asserts `included == derived − excluded` and that every exclusion names a covering suite and gives a reason. A suite can still be left out — it just cannot be left out *silently*, which is the failure this file keeps having. Both gates run on every push as part of the normal suite; only the per-mutant path skips them.

**Consequence for the number below: it is a floor.** Two covering gates do not run, so their kills go uncounted and the published score **understates** the suite's true fault-detection power. The baseline is unchanged at 56.94% because the effective include list is byte-identical to the one that produced it.

## Baseline (2026-08-17, seven-extractor scope)

| File | Mutation score | Killed | Survived | Timeout | No coverage |
|---|---:|---:|---:|---:|---:|
| **All (scoped)** | **56.94%** | 1,476 | 1,101 | 59 | 60 |
| `amounts.ts` | 64.74% | 228 | 124 | 7 | 4 |
| `jurisdictions.ts` | 62.81% | 229 | 141 | 21 | 7 |
| `dates.ts` | 60.91% | 287 | 174 | 9 | 16 |
| `parties.ts` | 58.99% | 292 | 199 | 13 | 13 |
| `sections.ts` | 51.92% | 27 | 21 | 0 | 4 |
| `obligations.ts` | 49.71% | 164 | 172 | 9 | 3 |
| `crossrefs.ts` | 46.80% | 249 | 270 | 0 | 13 |

(Mutation score = (killed + timeout) ÷ (killed + timeout + survived + no-coverage). The "covered" score, excluding no-coverage mutants, is 58.23% overall.

A further 25 mutants — 24 of them in `obligations.ts` — ended as runtime **errors**: the injected fault empties the `MODALS` constant, which makes `MODAL_RE` match the empty string, which makes `splitModalClauses`' `exec` loop stop advancing and hang the runner. Stryker excludes errors from the score. **This is a mutation-only artifact, not a product hazard** — every real `MODALS` entry is non-empty, so the pattern cannot match zero-length on any input; the `fuzz-boundary` guard exercises that same loop with the real constants. Note the consequence for the number: whether those 24 land as "error" or as "timeout" varies between runs, and timeouts count as killed — so `obligations.ts` oscillates a few points (49.71% here, 52.96% on the immediately preceding run of identical code) for that reason alone. Read it with that tolerance.)

**Read the aggregate against its scope, never across scopes** — and now also against its include list, since the same code scores differently depending on which covering suites run.

### History

| Date | Scope | Score | Break | Note |
|---|---|---:|---:|---|
| 2026-06-05 | dates + amounts | 51.26% → 55.65% | 48 | First run, then a survivor-fix pass (unit→day conversion, `before`-direction signing, scale-suffix multiplication, range-currency inheritance). |
| 2026-08-17 | dates + amounts | **47.59%** | 48 | **Gate broke.** Both files had grown without matching tests — but see the entry below: part of the "112 uncovered mutants" was the include-list defect, not missing tests. |
| 2026-08-17 | dates + amounts | 56.16% | 54 | Features covered as though entirely untested: `postfixCurrency`, `DAY_MONTH_YEAR`, `CURRENCY_OVERRIDE`. The first two already had dedicated suites that the config never ran. |
| 2026-08-17 | + crossrefs + sections | 52.34% | 50 | Scope widened; see the note above on comparing scores across scopes. |
| 2026-08-17 | + crossrefs + sections | **53.94%** | 52 | Pinned each external-citation branch in crossrefs (41 rows). crossrefs 42.86% → 46.80%. |
| 2026-08-17 | + jurisdictions + obligations + parties, **include list corrected** | 55.51% | 53 | Seven extractors. The include list now names every covering test file; that correction alone lifted amounts and dates (see above). Three real extractor bugs found while widening — a disclaimed governing law recorded as the chosen one, a bogus arbitration seat, and stranded punctuation in obligation actions — each fixed with a regression test. |
| 2026-08-17 | same seven | **56.94%** | 54 | Pinned the three governing-law clause-tail helpers, which carried one test row each against regexes with four to six distinct branches (jurisdictions 58.16% → 62.81%), and the two party phantoms found while mining the parties survivors — a comma-suffixed legal name registering twice, and a two-column signature block registering both signers as one party (parties 55.99% → 58.99%). |

The lesson the decay taught: a mutation score is not a one-time measurement. Adding code to a mutated file without adding tests lowers it mechanically, and because the job is weekly and off the push path, the failure sits unseen unless someone looks for it. The lesson the include-list defect taught is sharper: **a low score is a claim about the tests, and it is only trustworthy if the harness is actually running them.** Diagnose the harness before rewriting the suite.

The remaining survivors are the ratchet target, but crossrefs shows where that runs out: 41 rows pinning every external-citation branch moved it only 42.86% → 46.80%, because most of its ~270 survivors are equivalent mutants inside long alternations (`\s+` → `\s`, `[A-Za-z]+` → `[A-Za-z]`, dropped `^` anchors) that no realistic legal drafting distinguishes. The practical ceiling is well below 100%, and further gains there need a narrower, more testable decomposition of those regexes — not more test rows.

## Gate (regression-only, Step 124)

`stryker.config.json` sets `thresholds.break = 54` — a couple points under the measured 56.94%, with headroom for cross-platform drift. The scheduled job fails if the score drops below the floor; it never blocks on an unmet aspiration. **Ratchet up as survivors are killed** — the same measure-first discipline coverage and the v5 scoreboard use. The break threshold applies only in the mutation workflow, not the per-push gate.
