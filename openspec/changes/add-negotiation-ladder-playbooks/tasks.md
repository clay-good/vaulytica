# Tasks

- [ ] 1. Schema v3 in `custom-playbook.ts`: `rungs[]` (ordered predicates between ideal and acceptable), `party_role` + `role_variants`, deal-size bands on named thresholds, `approved_language` per position. v2 files parse unchanged (schema-version discriminated).
- [ ] 2. Extend `evaluateNegotiationPosture`: report the highest met rung (detail only); floor semantics untouched — invariant test: for any v3 playbook, `weakest_tier` ∈ the v2 value set and `below-acceptable` remains the only sub-floor value.
- [ ] 3. Role resolution: `--role <name>` / tab toggle selects the variant; unset role with role-variant positions → hard validation error (never a silent default).
- [ ] 4. Deal-size band resolution: from extracted contract value or `--deal-value`; the resolved band and its source are stamped into the posture block; unresolvable value → the position evaluates under its `default` band and the report says so.
- [ ] 5. Negotiation sheet: render full ladder with met rung highlighted; quote `approved_language` beside below-floor dimensions, attributed "from your playbook."
- [ ] 6. Coherence suites green unchanged; new golden for a v3 playbook run.
- [ ] 7. Docs: `docs/adding-a-playbook.md` v3 section with a complete example (vendor/customer roles, 3 rungs, 2 size bands).
- [ ] 8. Full gate green.
