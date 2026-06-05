# Testing architecture (v7 — the proof surface)

> Companion to [`spec-v7.md`](../spec-v7.md) Thrust B. Describes the *kinds* of test the suite runs and why each exists. For the legal-accuracy side (precision/recall vs. a credentialed annotator), see [`spec-v5.md`](../spec-v5.md) — that is a different claim.

The suite is **green ⇏ correct** by itself: a green example-based suite only says the inputs its authors thought of still pass. v7 adds the test kinds that probe the *logic*, each **measure-first, gate-second** (read the real number, then set a regression-only floor just under it — never an aspiration that blocks on day one).

## The layers, weakest-guarantee first

| Layer | Question it answers | Where |
|---|---|---|
| **Determinism guard** | Same input → same bytes, five runs in-process, three OSes? | `tests/integration/determinism-guard.test.ts` |
| **Golden corpus** | Does each fixture's `EngineRun` (result_hash + canonical JSON) still match the recorded output? | `tests/golden/`, `tests/integration/golden-output.test.ts` |
| **Code coverage** | Which lines/branches/functions of `src/` actually ran? | `npm run coverage` (V8 provider), gated in `ci.yml` |
| **Per-rule completeness** | Does every always-on rule both *fire* (positive) and *stay silent on a clean doc* (negative)? | `tests/integration/rule-completeness.test.ts` |
| **Property-based** | Do extractor/normalizer invariants hold for inputs *no author wrote down*? | `tests/integration/property-based.test.ts` (`fast-check`, fixed seed) |
| **Metamorphic** | Which input transformations must / must not change the output? | `tests/integration/metamorphic.test.ts` |
| **Node↔browser parity** | Does the accuracy harness produce the *same run* as the shipped pipeline? | `tools/accuracy/parity.test.ts` |
| **Schema fuzz + round-trip** | Does each zod schema *reject* corruption and round-trip valid input? | `src/dkb/schema-fuzz.test.ts` |
| **Report structure** | Does the DOCX/JSON actually *say the right things*, in the right order? | `src/report/docx.test.ts` |
| **Responsiveness** | No horizontal overflow per view-state at 320/390/768/1280 px? | `tests/e2e/responsiveness.spec.ts` (Playwright, post-deploy) |
| **a11y / keyboard / no-network** | WCAG 2.2 AA, keyboard reachability, zero cross-origin requests? | `tests/e2e/v3/`, `tests/e2e/v4/` (Playwright, post-deploy) |

## Why each layer earns its place

- **Coverage** tells you a line *ran*; it does not tell you a test would *catch a bug* on that line — that is what mutation testing (Steps 123–124, deferred to a scheduled job) measures. Coverage is the floor, not the ceiling.
- **Per-rule completeness** converts an unknown ("how many rules are actually proven?") into a closed set the build enforces. It is measure-first: it reports the gap, then ratchets to hard-fail as negatives are backfilled.
- **Property-based** testing catches the off-by-one and the empty-input crash the fixtures never hit — normalizer idempotence, exact/contiguous offsets, amount/date round-trips. Fixed seed → a failure reproduces exactly.
- **Metamorphic** testing encodes what the engine *means*: whitespace noise must not change `result_hash`; re-wrapping paragraphs must not change which rules fire. It already caught a real heading-whitespace determinism leak.
- **Node↔browser parity** is the structural guarantee behind v5's "reuses the real pipeline" claim. A divergence would mean the measured accuracy number does not describe shipped behavior — the exact failure v5 is built to prevent. The test drives a shared fixture through both `runReport` (browser) and `runDocument` (Node accuracy harness) and asserts a byte-identical `EngineRun`.
- **Schema fuzz** treats a schema's *rejection* job as first-class: mutate one field of a valid artifact to an invalid value and assert the schema rejects it with a useful error.
- **Report-structure** validation unzips the DOCX and asserts the OOXML — cover proof fields, severity-grouped findings, resolved citations, the verbatim posture block — so the product's actual output, not just its ZIP validity, is proven.
- **Responsiveness-as-a-test** turns the recurring manual audit into a coarse but durable CI gate (it catches overflow, not ugliness), kept *alongside* the periodic visual audit per spec-v7 Open Q #7.

## The posture corollary

A new test may never weaken determinism to pass. If a metamorphic or property test is flaky, the bug is in the engine or the test's oracle — never in the determinism contract. The contract is the thing under test, not a thing to relax.
