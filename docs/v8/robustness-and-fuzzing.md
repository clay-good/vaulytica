# Robustness & fuzzing (v8 — the resilience surface)

> Companion to [`spec-v8.md`](../spec-v8.md) Thrust A. Describes the *kinds* of robustness test the suite will run, the hardening contract every public function must satisfy, and why bounds — never timeouts — are the only posture-legal way to make a deterministic engine safe against resource exhaustion. For the internal-logic proof side (coverage, property, metamorphic, parity), see [`v7/testing-architecture.md`](../v7/testing-architecture.md); that is a different claim.

The v7 suite is **green on valid input ⇏ safe on invalid input**. Every fixture is a *plausible* document; none is hostile. v8 Thrust A adds the test kinds that probe the **API boundary** under inputs designed to break it, each **measure-first, gate-second**: build the adversarial corpus, run it against the current code, record exactly what crashes or runs unbounded, *then* write the guard and ratchet the gate just under the now-safe baseline.

## The hardening contract

Every public entry point — ingest, extract, engine/consistency runners, playbook validator/interpreter, report/bundle builders — must satisfy, for **any** input:

| Property | Means | Counter-example it forbids |
|---|---|---|
| **No crash** | Returns a value or throws a *typed, caught* error with an actionable message. | An uncaught `RangeError` from stack overflow aborting the pipeline. |
| **No unbounded work** | Time and peak memory bounded by an explicit function of a *capped* input — never by an attacker-controlled quantity. | A 200 KB zip inflating to 4 GB; a 50-digit amount driving `decimal.js` allocation. |
| **Deterministic rejection** | Over-cap input is rejected the same way every time, naming the cap and the observed value. | A frozen spinner with no message; a different outcome on a fast vs. slow machine. |
| **No posture cost** | The guard is a pure function of the input — no clock, no randomness, no silent truncation of a `result_hash`-bearing computation. | A wall-clock timeout; a partial result that looks complete. |

## Why bounds, not timeouts

The determinism contract is *same input → same bytes, on any machine, forever*. A timeout breaks it: a document that finishes in 4 s on a workstation and is killed at 3 s on a phone yields two results from one input — the exact non-determinism the whole product forbids. So Thrust A bounds the **input** (size, depth, count, magnitude, ratio) so the **work** is bounded as a consequence, and never bounds the **clock**:

- A **capped** input runs in bounded time on every machine.
- An **uncapped** input is *rejected deterministically* before the work begins.

A timeout would be the easy fix and the wrong one. The posture corollary from [`spec-v8.md`](../spec-v8.md) §3 is firm: *a guard may never become non-deterministic to be safe.*

## The caps (one place to read them all)

Each cap is set ~1 order of magnitude above the largest legitimate real-world input, so no real user reaches it. Final names/values land with the code; the design intent:

| Cap | Guards | Layer |
|---|---|---|
| `MAX_DOCUMENT_BYTES` | Direct `ingestDocxBuffer` / `ingestPdfBuffer` (single-doc path bypasses the bundle planner's `MAX_FILE_BYTES`). | ingest |
| `MAX_PASTE_CHARS` | `ingestPaste` (no length check today). | ingest |
| `MAX_SECTION_DEPTH` | `normalize` / `normalizeSection` / extractor `walk` recursion (no depth cap → stack overflow on nested DOCX/HTML). Flatten-and-warn past the cap. | ingest / extract |
| `MAX_OCR_PAGES` | `ingestPdf` OCR loop (every page, no ceiling). Honest partial past the cap. | ingest |
| `MAX_COMPRESSION_RATIO` + incremental byte budget | `extractZipEntries` (`unzipSync` materializes the full payload before any size check — zip bomb). Abort mid-inflate. | ingest |
| `MAX_AMOUNT_DIGITS` + `NaN`/`Infinity` drop | `extractAmounts` (`Decimal.set({ precision: 50 })`; huge-magnitude allocation). | extract |
| `MAX_PLAYBOOK_JSON_BYTES` (pre-parse) · `MAX_CUSTOM_RULES` · per-string caps | `parseCustomPlaybookJson` / `CustomPlaybookSchema` (no byte/count/length cap). | playbooks |
| `BUNDLE_CROSS_DOC_TOP_N` | Bundle cross-document appendix (per-doc findings cap at `BUNDLE_TOP_N`; cross-doc is uncapped). Honest "N more" footer. | report |

Every cap surfaces honestly: a hard reject is a deterministic ingest-rejection (existing path + UI banner); a degrade-to-partial carries a `capped: true` flag and a visible "N more not shown / pages skipped" note. **No cap silently changes a `result_hash`** — the extracted-data stream is not in the hash, so the amount/depth guards are zero-churn; the bundle-cross-doc footer is render-side.

## The test layers, weakest-guarantee first

| Layer | Question it answers | Where |
|---|---|---|
| **Adversarial fixture corpus** | Does each *known* pathological shape get rejected/bounded, not crash? | `tests/fixtures/adversarial/` (deterministic builders) + targeted unit tests |
| **Boundary properties** | For inputs *no author wrote down*, does every public function return-or-typed-throw, never throw uncaught, and terminate within a bounded op-count? | `tests/integration/boundary-fuzz.test.ts` (`fast-check`, fixed seed) |
| **What-breaks baseline** | Which public functions are *currently* unguarded? (measure-first, committed honestly) | the Step 127 baseline artifact |

### The adversarial corpus (Step 127)

Deterministic builders — **no binary blobs in the repo** (mirrors the existing fixture-builder pattern and the v5 privacy guard: a generated fixture is reviewable as code and cannot smuggle a real document in):

- a DOCX/tree nested past `MAX_SECTION_DEPTH`;
- a zip bomb (small archive, huge inflation);
- a fifty-significant-digit amount document;
- a ReDoS-bait document (thousands of near-matches of the range-date and range-amount patterns);
- a 100,000-rule custom playbook;
- a malformed-but-parseable JSON playbook;
- the degenerate trio: empty, single-glyph, all-whitespace.

### The boundary properties (Steps 133–134)

`fast-check`, fixed seed (a failure reproduces exactly), pure functions so it runs on the per-commit path with no IO. For each public entry point, three invariants:

1. **Returns or typed-throws** — never an uncaught exception that escapes the call.
2. **Never uncaught** — a thrown error is one of the typed, caught rejection classes; a downstream `await` never sees an unhandled rejection.
3. **Bounded op-count** — the function terminates within an explicit operation budget for its capped input (a test-only counter/watchdog, **never** in the shipped path — it is an oracle, not a runtime timeout).

The generators include the corpus shapes plus randomized structure (random nesting, random repetition of the bait patterns, random oversized strings). Step 133 *measures* (records the baseline of what breaks); Step 134 *gates* (the property becomes regression-only once the §-7–11 guards land).

## The posture corollary

This is the boundary analog of v7's metamorphic suite. v7 pins what the engine *means* on valid input ("whitespace noise must not change `result_hash`"); v8 pins how it *behaves* on invalid input ("a zip bomb must be rejected, not inflated"). In both, **the contract is the thing under test, never a thing to relax** — if a boundary property is flaky, the bug is in the engine or the guard, never in the determinism contract. A guard that has to read the clock to pass has failed the design, not the test.
