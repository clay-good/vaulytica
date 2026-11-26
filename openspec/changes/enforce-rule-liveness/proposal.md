# enforce-rule-liveness

## Why

A deterministic reviewer's whole claim is that silence means "checked, and clean." A dead rule
breaks that claim quietly: it runs, finds nothing, and is indistinguishable from a rule whose
clause was present. Nothing in the product fails when that happens.

The repo already proves this is the dominant defect class — a rule written in one letter case,
one word order, or blinded by "30 (thirty) days" went on shipping and reporting nothing — and
every one of those was found by a hand-authored sweep in a later session, never by the engine
noticing it had gone quiet.

One guard covers part of the catalog today. `presence-rule-satisfiable.test.ts` proves that each
of the ~800 ungated `presence()` rules fires on a contentless document. Measured against the live
catalog:

| | rules |
| --- | --- |
| catalog (base v1–v7 + opt-in packs) | 1,973 |
| covered by the presence guard | 802 |
| **not covered by any liveness guard** | **1,127** |
| of those, never observed firing on any of the 363 specimens | **127** |

The 127 are not all dead — most want a context the sweep does not supply (a court profile, an
asserted readability standard, a typo, a point size a `.txt` file cannot carry). That is exactly
the trap: "it needs something the sweep does not supply" is a true fact that has twice been
paired with the false conclusion "so it cannot be checked." A rule that needs a special context
needs that context *committed and executed*, not a sentence excusing it.

## What Changes

- A liveness ratchet over the **whole** catalog, in two tiers, both runtime (no static scanning —
  a grep for a pattern cannot tell whether a rule ever returns a finding):
  - **Tier 1 — corpus.** Sweep the 363 specimens. A rule that emits a finding on any of them is
    live, and needs nothing else, for ever.
  - **Tier 2 — committed fixture.** Every rule tier 1 does not reach must be named in a fixture
    registry that supplies a `RuleContext` the guard then *runs*, asserting the rule fires. The
    registry holds contexts, not excuses: there is no prose exception list, and an entry that
    stops making its rule fire fails the build.
- A rule in neither tier fails the ratchet. Adding a rule with no firing evidence fails the
  ratchet. That is the always-on part: the gap closes by default instead of by remembering.
- The registry's own health is asserted: it must be non-empty, every entry must name a rule that
  exists in the catalog, and an entry whose rule has become tier-1 live is reported as redundant
  rather than silently carried.

## Impact

- Affected specs: `rule-liveness` (new capability spec)
- Affected code: new `tests/integration/rule-liveness.test.ts`,
  `tests/integration/_liveness-fixtures.ts` and `tests/fixtures/liveness/`; no `src/` change
- Result: 117 silent rules → 28. The 28 are recorded in a `KNOWN_SILENT` ledger that is asserted
  in BOTH directions, so it can only shrink: a rule that starts firing fails until its entry is
  deleted, and a rule that goes quiet fails because it is not on the list. They are findings, not
  fixture gaps — two CHOICE rules are shadowed into permanent silence by a sibling that fires
  first, a `pack()` column is satisfied by its own applicability trigger, and one rule guards on a
  condition its extractor never produces. Fixing them changes rules, which moves `result_hash` on
  every document that draws them, so that work is deliberately not bundled here
- Risk: none to outputs — the ratchet is test-only and emits no findings, so no `result_hash`
  moves. Cost is one ~20s sweep in the suite.
- Deliberately **not** in scope: the accuracy corpus (`corpus/`) stays out, because the
  corpus ⟂ fixtures invariant exists so the engine is never graded on documents it was authored
  against. Liveness is not grading, but borrowing the corpus here would erode that boundary.
