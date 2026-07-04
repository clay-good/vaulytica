# add-negotiation-ladder-playbooks

## Why

Deal teams keep positions as multi-tier ladders with role- and size-dependent floors; the market consensus is "invest in the playbook first — clause standards, fallback positions, escalation triggers." Vaulytica's custom playbook stops short three ways (`src/playbooks/custom-playbook.ts`): the ladder has exactly two predicate rungs (`ideal`, `acceptable`) with `walk_away` as prose; one playbook cannot express both sides of a deal (no party-role switch — you author two files); and positions cannot vary by deal size (thresholds are static). Separately, teams cannot carry their own approved fallback language into the report — the 23 built-in model clauses cover ~2% of rules. All four are schema/evaluation extensions of machinery that already exists; the binary floor (`below-acceptable` as the only sub-floor rung) stays untouched so all 29 coherence commands remain valid.

## What Changes

- Custom playbook schema v3 (additive; v2 files stay valid): (a) optional intermediate rungs between `ideal` and `acceptable` — each a predicate; the *floor* stays `acceptable`, so posture/coherence semantics (`weakest_tier`, binary floor) are unchanged and intermediate rungs only refine the "above" report detail; (b) `party_role` on the playbook plus per-position `role_variants`, selected by a `--role` flag / tab toggle; (c) named thresholds may carry deal-size bands (`when: contract_value >= X`) resolved from the document's extracted amounts or an explicit `--deal-value` override — resolution is deterministic and stamped into the report; (d) per-position `approved_language` — the *team's own* pre-approved fallback text, quoted (clearly attributed to the playbook, never generated) beside a below-floor finding.
- The negotiation sheet renders the full ladder with the met rung highlighted and the team's approved language beside each below-floor dimension.

## Impact

- Affected specs: `playbooks`
- Affected code: `src/playbooks/custom-playbook.ts` (schema + validation), posture evaluation (`evaluateNegotiationPosture`) for rung refinement and role/band resolution, `src/report/negotiation-sheet.ts`, CLI flags; extensive tests
- Risk: must not disturb the binary floor contract — guarded by the existing coherence test suites plus new invariants (a v3 playbook's `weakest_tier` values remain drawn from the v2 value set).
