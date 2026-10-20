# Tasks

- [ ] 1. Fixtures: a final DOCX and (a) a text-layer PDF of its executed form with filled blocks and dates, (b) the same with one changed figure, (c) the same with an added signatory, (d) an image-only scan with a seeded low-confidence word; a two-folder closing set with one unpaired file and one title tie.
- [x] 2. `src/report/conformity.ts`: allowance classifier over paragraphs (signature window reuse, blank-to-date fill, initials, cover pages, furniture, watermark words); verdict; canonical table and `conformity_hash`.
- [x] 3. `clause-diff.ts`: accept an allowance predicate so set-aside paragraphs are listed, not diffed; the plain comparison path unchanged (goldens hold).
- [ ] 4. OCR confidence join: unverified differences and the could-not-determine verdict in the browser; CLI refusal for image-only PDFs.
- [ ] 5. `compare --executed` and `--executed-set` with `--fail-on-nonconformity`; title pairing via the matcher; stream contract respected.
- [ ] 6. Renderers: Markdown, JSON, DOCX section; browser affordance and Word deliverable; cross-surface hash parity on text-layer inputs.
- [x] 7. Metamorphic relations: filling blanks in the final must not change the verdict; altering any non-allowance paragraph must; format transforms on the executed side must not.
- [ ] 8. Docs: `reference.md` comparison section, `ci-integration.md` closing-set example; `/known-limits` sentence for image-only scans headless.
- [ ] 9. Full gate green.

## Progress

- 9.968.0 shipped slice A: the allowance classifier, verdict and `conformity_hash` (task 2), and `buildClauseDiff`'s `exclude` predicate (task 3; the plain path is unchanged). Also `compare --executed` with `--fail-on-nonconformity` for one pair (the pair half of task 5), the Markdown and JSON sections (part of task 6), and the corpus relations (task 7: executing every specimen is identical; changing a figure is caught 209/209).
- The fixtures are text: `src/report/_conformity-fixtures.ts` holds a final and its executed copy; the variants (changed figure, added signatory, dropped and added clause) are built in the tests. Task 1's PDF and scan fixtures are still to make.
- The CLI refuses an image-only signed copy (no text layer). `/known-limits` already says the CLI runs no OCR.
- Open: `--executed-set` and title pairing (rest of task 5); the OCR confidence join and the browser (tasks 4 and 6); the DOCX section; task 1's PDF fixtures; the `ci-integration.md` closing-set example.
