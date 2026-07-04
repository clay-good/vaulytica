# fix-playbook-diff-completeness

## Why

`vaulytica diff a.json b.json --exit-code` is documented (README) as exiting
`1` when playbooks differ — teams gate CI on it to catch unauthorized playbook
drift. But `src/playbooks/diff.ts` (written at spec-v8) diffs only
`metadata`, `rule_selection`, `rule_overrides`, `thresholds`,
`required_clauses`, and `custom_rules`; `negotiation_positions` (added at
spec-v10) is never compared — zero mentions in the file. Verified live: two
playbooks whose only difference is a walk-away floor
(`negotiation_positions[0].acceptable.value` 6→4) produce `_No structural
differences._` and **exit 0**. The gate silently passes drift in exactly the
field the entire posture/coherence family exists to police. The existing diff
tests only cover the fields diff knows about, so the suite stays green.

## What Changes

- `diff` compares every field of the playbook schema, including
  `negotiation_positions` (per-position: rung values, floors, fallback
  language, role/deal-size conditionals).
- A schema-completeness guard: a test derives the set of top-level playbook
  keys from the schema/type and fails if `diff` lacks a comparator for any of
  them — so the next added field cannot repeat this.
- Diff output renders position changes in attorney terms ("acceptable floor
  for LIMITATION-OF-LIABILITY moved 6 → 4"), consistent with the existing
  section renderers.

## Impact

- Affected specs: `playbook-tooling` (new capability spec)
- Affected code: `src/playbooks/diff.ts`, `src/playbooks/diff.test.ts`
- Risk: none to analysis output; `diff --exit-code` starts failing on drift it
  previously missed, which is the fix. Coordinates with
  `add-negotiation-ladder-playbooks` (multi-rung ladders extend the same
  field — its spec should note diff coverage extends with it).
