# Tasks

- [x] 1. Failing test first: floor-drift fixture pair through the real CLI
  (`diff --exit-code`) must exit 1 (exits 0 today). *(Pinned in
  `src/playbooks/diff.test.ts` and reproduced live: acceptable floor 6 → 4
  now renders "acceptable floor for Liability cap moved 6 → 4" and exits 1.)*
- [x] 2. Add the `negotiation_positions` comparator to
  `src/playbooks/diff.ts` (per-position, rung-level granularity) and the
  attorney-terms renderer. *(Per-dimension added/removed/changed; ideal and
  acceptable rungs compared independently; same-metric numeric-threshold
  moves render as moved floors, other predicate changes state before/after;
  guidance changes reported.)*
- [x] 3. Add the schema-derived completeness guard test over playbook
  top-level fields. *(`CUSTOM_PLAYBOOK_FIELDS` is now exported from the zod
  schema's own shape; the guard fails naming any schema field without a
  declared comparator, so the next added field cannot repeat this.)*
- [x] 4. Note in `add-negotiation-ladder-playbooks` coordination: ladder
  extensions to `negotiation_positions` inherit diff coverage via the guard.
  *(Already present in that proposal's Impact section from the wave-3 spec
  corrections; the guard mechanism it references now exists.)*
- [x] 5. Full gate green. *(typecheck, lint, format:check, 3,689 tests /
  261 files, build.)*
