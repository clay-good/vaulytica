# wire-jurisdiction-id-resolution — tasks

- [x] 1. Measure before deciding: how many extracted jurisdiction entries would resolve, and how
      many findings would move. *(371/404 entries resolve, 91.8%. Findings moved: ZERO — 147 of the 149 documents with both clauses are already raw-equal. The prediction in `retire-shadowed-choice-rule` was wrong.)*
- [x] 2. Move the state-name resolver into `src/dkb/jurisdiction-ids.ts`, exported as a
      `DkbLookup`; `state-overlays.ts` delegates to it. *(`src/dkb/jurisdiction-ids.ts`. The drift guard compares its key set against `US_STATE_PATTERN`, a second state list written independently in `extract/jurisdictions.ts` — both hold the same 51.)*
- [x] 3. Pass the resolver at both product `extractAll` call sites in `src/ui/pipeline.ts`. *(Both sites wired. 🥇 The static guard found a THIRD: `src/engine/_test-fixtures.ts`, the shared rule-test context builder, which would have graded every rule against `undefined` ids while the product filled them — the s35 harness-divergence shape. Wired too.)*
- [x] 4. Reach guard: assert the product pipeline populates `jurisdiction_id`, with a vocabulary
      written independently of the resolver's map. *(`tests/integration/jurisdiction-id-reach.test.ts`, static + runtime. Proved by failing: unwiring the lookup turns 4 of its 5 tests red.)*
- [x] 5. Pin the two latent behaviours: `governing_law_in` with `allowed: ["us-de"]`, and the DOCX
      jurisdiction id column. *(🥇 Both were latent defects, not hypotheticals. `allowed: ["us-de"]` reported a compliant Delaware document VIOLATED — confirmed red before the fix. The DOCX id column printed `—` in every report ever exported.)*
- [x] 6. Prove `CHOICE-004`'s id branch suppresses, at the unit level, and record that no specimen
      reaches it. *(`CHOICE-004.test.ts`, which did not exist — 004 was tested only through 003's and 012's suites. The id branch is unit-tested and recorded as reached by no corpus document.)*
- [x] 7. Correct every docstring asserting the lookup is unwired. *(Four: `custom-interpreter.ts`, `extract/jurisdictions.ts`, `state-overlays.ts` (removed with the map), `rule-liveness.test.ts`.)*
- [x] 8. Regenerate goldens; verify no finding text changed. *(No regeneration needed — NOTHING
      moved. 696/697 test files green on the first full run; the one failure was
      `mutation-scope` naming the new resolver suite. 🥇 The reason no golden moved is itself a
      finding: `result_hash` excludes extracted data and `artifact-digests` covers HTML + SARIF,
      not the DOCX — so the primary deliverable has no byte-pinned coverage, which is how an
      always-dash column survived. `docx.test.ts` asserts `blob.size` only.)*
