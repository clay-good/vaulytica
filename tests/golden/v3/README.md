# tests/golden/v3 — v3 golden-output corpus

This directory carries the golden-output regression suite for the v3
rule sets, per [spec-v3.md](../../../docs/spec-v3.md) Part X and Step 34.

## Layout

```
tests/golden/v3/
  fixtures/                # input documents (.txt paste, .docx binary)
    <name>.{txt,docx}      # the contract under test
    <name>.{txt,docx}.playbook   # optional sidecar forcing a playbook id
  expected/                # one canonicalized EngineRun JSON per fixture
    <name>.json
  golden.test.ts           # the assertion harness
  _pipeline.ts             # the pipeline runner (v2 LAUNCH_RULES + V3_RULES)
  README.md                # this file
```

Each fixture is the smallest reproduction of a single coverage cell. The
`.playbook` sidecar exists to force a v3 playbook id when the
auto-detector picks a v2 fallback — for example a tiny BAA-flavored
fixture might match `mutual-nda` on length alone, so the sidecar pins
it to `baa`.

## Regenerating goldens

After an intentional rule change (rule wording, severity, citation,
ordering, or hash composition), re-baseline the affected fixtures:

```
VAULYTICA_REGEN_GOLDEN=1 npx vitest run tests/golden/v3
```

Then review the diff in `expected/` and commit. **Never** auto-accept
without reading the diff — a golden bump is the audit trail for a rule
change.

## Determinism

The harness runs every fixture twice in-process and asserts
byte-identical canonical bytes (not just `result_hash`). This is the v3
analogue of the v2 cross-OS determinism guarantee in
`tests/integration/determinism-guard.test.ts`.

## Expansion plan

The Part-X corpus (spec-v3.md §15) sketches ~155 fixtures across the
five regulated-agreement families plus pairs. Future work lands the
remaining fixtures one family at a time:

- BAA: 25 + ~15 hand-built fail cases (Step 23 baselines, Step 34 corpus)
- DPA: 25 + ~20 fail cases (Steps 24–25 baselines)
- MSA: 15 + ~15 fail cases (Step 28)
- NDA: 15 + ~10 fail cases (Step 27)
- EULA / ToS / privacy policy / COI: 10 + 10 + 10 + 5 (Step 29)
- Two-document pairs: 20 (Step 31 consistency engine baselines)

Each landing follows the same recipe: drop the document into
`fixtures/`, optionally add a `.playbook` sidecar, then run with
`VAULYTICA_REGEN_GOLDEN=1` and commit the resulting `expected/*.json`.
