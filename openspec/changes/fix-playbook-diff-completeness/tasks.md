# Tasks

- [ ] 1. Failing test first: floor-drift fixture pair through the real CLI
  (`diff --exit-code`) must exit 1 (exits 0 today).
- [ ] 2. Add the `negotiation_positions` comparator to
  `src/playbooks/diff.ts` (per-position, rung-level granularity) and the
  attorney-terms renderer.
- [ ] 3. Add the schema-derived completeness guard test over playbook
  top-level fields.
- [ ] 4. Note in `add-negotiation-ladder-playbooks` coordination: ladder
  extensions to `negotiation_positions` inherit diff coverage via the guard.
- [ ] 5. Full gate green.
