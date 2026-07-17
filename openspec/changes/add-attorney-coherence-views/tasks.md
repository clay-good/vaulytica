# Tasks

- [x] 1. `tools/cli/posture-review.ts`: verify the sequence once (shared `verifyCoherenceSequence`, unchanged), then compose the trend/movement, matrix, and weak-front/exposure report modules; render the three sections in deal language with drill-down command names; `--format json` nests them under `posture_review` with a namespaced `posture_review_hash`.
- [x] 2. Dispatcher + USAGE entry; gate flags pass through (`--fail-on-blackout-round`, regression gates) with unchanged exit-code semantics.
- [x] 3. Tests: composition equals the individual commands' outputs (no recomputation drift), JSON nesting, determinism, ladder/tamper refusals identical to siblings.
- [x] 4. Tab posture card adopts the three headings (Position drift / Exposure map / Weakest front). *(The two movement cards — v11 draft-over-draft and v13 round-over-round — are "Position drift"; the v12 coherence card is "Weakest front" (its binding-floor line is exactly that view, and its aligned/divergent summary keeps the consistency answer); each card's note now leads with the attorney question. "Exposure map" has no tab surface — it needs an N-round archive the tab never holds; `posture-review` / `coherence-matrix` cover it.)*
- [x] 5. Write `docs/posture-for-attorneys.md`; sweep site + README feature copy for volatility/relapse/tenure vocabulary and replace with the attorney phrasing (internal spec docs untouched). *(Sweep done: site feature copy carries no internal metric names; README gains the `posture-review` front-door example in the CLI cheat sheet + a Docs-table row, and both dispatcher command lists now include `posture-review` (count corrected thirty-three → thirty-four). The deep per-spec README sections keep their internal names, as spec'd.)*
- [x] 6. Full gate green.

## Deviations

- **Everything shipped.** `posture-review` (composition + JSON nesting + tests),
  `docs/posture-for-attorneys.md`, the tab card headings (follow-up, 2026-07-17),
  and the site/README sweep (same follow-up). The 29 sibling commands and all
  internal spec docs keep their names. The tab has no "Exposure map" surface —
  that view needs an N-round archive the tab never holds; the CLI covers it.
- **No recomputation drift** is pinned by a test: the nested `position_drift`
  equals the standalone `coherence-trend --format json` output byte-for-byte.
