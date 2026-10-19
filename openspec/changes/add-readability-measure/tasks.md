# Tasks

- [ ] 1. Syllable counter: rules plus a committed exception list; measure against a 5,000-word reference list and commit the accuracy figure; version constant.
- [ ] 2. `src/report/readability.ts`: tokenization under the model act's rules over the tree (headings and captions excluded, signature block and TOC excluded), score, longest sentence, exclusions list; render-side block in JSON, DOCX appendix, HTML.
- [ ] 3. DKB `readability_standards`: read each state's statute at its official source (start with NY, FL, MI, ME, CO, TX, CA, WV, and the model-act states), record threshold, scope, TOC and type-size requirements; provenance gate.
- [ ] 4. `READ-001`, `READ-002`, `READ-003` assertion-gated; register `readability-<state>` and `readability-ny-consumer`; CLI `--readability`; browser selector.
- [ ] 5. Fixtures: a policy under and over threshold, a long policy without a TOC, an uncaptioned lease; property test that the block never changes `result_hash`.
- [ ] 6. Docs: `reference.md` section, `/known-limits` sentence on sampling and exclusions not applied, `deadlines.md`-style note `readability.md` with the formula and the statute table.
- [ ] 7. Full gate green.
