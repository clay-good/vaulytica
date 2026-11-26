# retire-shadowed-choice-rule

## Why

`rule-liveness.test.ts` recorded three CHOICE rules as having no firing evidence and attributed
all of them to one cause: each defers to `CHOICE-004` and then tests substantially CHOICE-004's
own condition, a governing-law/venue split. That was a true observation with the wrong conclusion
attached, and testing it rather than trusting it split the three apart:

| rule | verdict |
| --- | --- |
| `CHOICE-004` | live — owns the plain law/venue split |
| `CHOICE-012` | **never dead.** 004 and 009 read `jurisdictions.find(venue)` — the FIRST venue only. 012 scans every venue entry, so a document whose first venue matches the governing law and whose second does not silences 004 and fires 012. It wanted a fixture, not a rule change. |
| `CHOICE-009` | **dead, and for a stronger reason than shadowing.** No caller in the product passes `jurisdictionLookup` to `extractAll`, so `lookup` is always the default `() => undefined` and `jurisdiction_id` is undefined on every entry. With no ids, 009's `same` reduces to a case-insensitive raw-text compare — exactly 004's test, which runs first. All four of its own tests asserted `toBeNull()`. |

A rule whose entire test suite proves it never fires is not a rule. Worse, it was reported to
readers as part of the catalog: the execution log said it RAN and found nothing, which is the
product's way of saying "checked, and clean."

## What Changes

- `CHOICE-009` is retired: rule, registration and its test file are deleted. `CHOICE-004` already
  reports its defect, with a better-calibrated explanation.
- `tests/fixtures/liveness/defects-multi-venue.txt` — a second venue clause that contradicts the
  first, which is the case `CHOICE-012` alone can see. Both ids leave the known-silent ledger.
- Count pins follow: `LAUNCH_RULES` 131 → 130, `CHOICE` 12 → 11, the liveness catalog pin
  1,946 → 1,945, and the engine's `execution_log` length.

## Impact

- Affected specs: `rule-liveness` (the ledger shrinks; no requirement changes)
- Affected code: `src/engine/rules/choice-and-venue/CHOICE-009.{ts,test.ts}` deleted,
  `src/engine/rules/index.ts`, four tests that asserted 009's silence, two historical comments
- **`result_hash` moves on every run**, because `execution_log` is inside the hash and it lost an
  entry — two runs that evaluated different rule sets are different analyses. Verified
  semantically rather than by eye: 327 goldens differ ONLY by `CHOICE-009` leaving the execution
  log, 17 are identical once hashes are stripped, and the 10 changed keys in
  `artifact-digests.json` are all digests of artifacts that embed the hash. **No finding changed
  anywhere** — which is provable a priori, since the rule never produced one.
- Done, in `wire-jurisdiction-id-resolution`. `jurisdiction_id` was dead product-wide: nothing
  supplied `jurisdictionLookup`, so the id branches in `CHOICE-004` and the extractor's seven
  `lookup(raw)` call sites were unreachable. ⚠️ The cost was stated here as "would change routing
  and findings, not just hashes" — **measured, that was wrong: it moves no finding on any of the
  377 committed documents.** Predicting a blast radius is not measuring one.
