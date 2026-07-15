# Tasks

- [x] 1. `tools/cli/posture-review.ts`: verify the sequence once (shared `verifyCoherenceSequence`, unchanged), then compose the trend/movement, matrix, and weak-front/exposure report modules; render the three sections in deal language with drill-down command names; `--format json` nests them under `posture_review` with a namespaced `posture_review_hash`.
- [x] 2. Dispatcher + USAGE entry; gate flags pass through (`--fail-on-blackout-round`, regression gates) with unchanged exit-code semantics.
- [x] 3. Tests: composition equals the individual commands' outputs (no recomputation drift), JSON nesting, determinism, ladder/tamper refusals identical to siblings.
- [ ] 4. (DEFERRED — UI copy follow-up) Tab posture card adopts the three headings (Position drift / Exposure map / Weakest front).
- [x] 5. (docs page done; site/README vocab sweep DEFERRED) Write `docs/posture-for-attorneys.md`; sweep site + README feature copy for volatility/relapse/tenure vocabulary and replace with the attorney phrasing (internal spec docs untouched).
- [x] 6. Full gate green.

## Deviations

- **CLI command + docs shipped; tab card headings and the site/README vocab
  sweep deferred.** `posture-review` (composition + JSON nesting + tests) and
  `docs/posture-for-attorneys.md` ship. Renaming the tab posture card to the
  three headings and replacing volatility/relapse/tenure vocabulary in the
  site + README feature blurbs are UI/marketing-copy follow-ups (consistent
  with prior UI deferrals); the 29 sibling commands and all internal spec docs
  keep their names.
- **No recomputation drift** is pinned by a test: the nested `position_drift`
  equals the standalone `coherence-trend --format json` output byte-for-byte.
