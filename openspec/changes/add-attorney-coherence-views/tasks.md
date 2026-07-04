# Tasks

- [ ] 1. `tools/cli/posture-review.ts`: verify the sequence once (shared `verifyCoherenceSequence`, unchanged), then compose the trend/movement, matrix, and weak-front/exposure report modules; render the three sections in deal language with drill-down command names; `--format json` nests them under `posture_review` with a namespaced `posture_review_hash`.
- [ ] 2. Dispatcher + USAGE entry; gate flags pass through (`--fail-on-blackout-round`, regression gates) with unchanged exit-code semantics.
- [ ] 3. Tests: composition equals the individual commands' outputs (no recomputation drift), JSON nesting, determinism, ladder/tamper refusals identical to siblings.
- [ ] 4. Tab posture card adopts the three headings (Position drift / Exposure map / Weakest front).
- [ ] 5. Write `docs/posture-for-attorneys.md`; sweep site + README feature copy for volatility/relapse/tenure vocabulary and replace with the attorney phrasing (internal spec docs untouched).
- [ ] 6. Full gate green.
