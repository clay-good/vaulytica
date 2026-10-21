# Tasks

- [ ] 1. Fixtures: a final DOCX and (a) a text-layer PDF of its executed form with filled blocks and dates, (b) the same with one changed figure, (c) the same with an added signatory, (d) an image-only scan with a seeded low-confidence word; a two-folder closing set with one unpaired file and one title tie.
- [x] 2. `src/report/conformity.ts`: allowance classifier over paragraphs (signature window reuse, blank-to-date fill, initials, cover pages, furniture, watermark words); verdict; canonical table and `conformity_hash`.
- [x] 3. `clause-diff.ts`: accept an allowance predicate so set-aside paragraphs are listed, not diffed; the plain comparison path unchanged (goldens hold).
- [ ] 4. OCR confidence join: unverified differences and the could-not-determine verdict in the browser; CLI refusal for image-only PDFs. **Blocked:** no surface runs OCR (see 9.977.0 below); the refusal half is done.
- [x] 5. `compare --executed` and `--executed-set` with `--fail-on-nonconformity`; title pairing via the matcher; stream contract respected.
- [x] 6. Renderers: Markdown, JSON, DOCX section; browser affordance and Word deliverable; cross-surface hash parity on text-layer inputs.
- [x] 7. Metamorphic relations: filling blanks in the final must not change the verdict; altering any non-allowance paragraph must; format transforms on the executed side must not.
- [x] 8. Docs: `reference.md` comparison section, `ci-integration.md` closing-set example; `/known-limits` sentence for image-only scans headless.
- [ ] 9. Full gate green.

## Progress

- 9.968.0 shipped slice A: the allowance classifier, verdict and `conformity_hash` (task 2), and `buildClauseDiff`'s `exclude` predicate (task 3; the plain path is unchanged). Also `compare --executed` with `--fail-on-nonconformity` for one pair (the pair half of task 5), the Markdown and JSON sections (part of task 6), and the corpus relations (task 7: executing every specimen is identical; changing a figure is caught 209/209).
- The fixtures are text: `src/report/_conformity-fixtures.ts` holds a final and its executed copy; the variants (changed figure, added signatory, dropped and added clause) are built in the tests. Task 1's PDF and scan fixtures are still to make.
- The CLI refuses an image-only signed copy (no text layer). `/known-limits` already says the CLI runs no OCR.
- 9.974.0 finished task 5: `compare --executed-set <final-dir> <signed-dir>` (`compareExecutedSet` in the API, the pure pairing and table in `src/report/closing-set.ts`). Files pair by the first title line that is not a legend, lowercased with punctuation folded; ties and unpaired files are listed, never paired. A pair the CLI cannot read (image-only scan) is an `unreadable` row. The set's `conformity_hash` covers the rows (each with its pair's own hash), the unpaired files and the ties, with folder-relative `/` paths. `--fail-on-nonconformity` exits 2 on any difference, unpaired file, tie or unreadable copy. Markdown and JSON only. The `ci-integration.md` closing-set example is in (part of task 8). A "pages OCR'd" column is not included: the CLI runs no OCR, so it would always be 0.
- Open: the OCR confidence join and the browser (tasks 4 and 6); the DOCX section; task 1's PDF fixtures; the `/known-limits` sentence and the `reference.md` comparison section (rest of task 8).

## Progress — 9.977.0

Task 4 rests on a premise that is false: the proposal says "the browser already runs OCR on image-only PDFs", but `prepareDocument` ingests every PDF with `allowOcr: false` (fix-privacy-claim-accuracy: tesseract's worker, wasm and language model would load from a third-party CDN, which the shipped `connect-src 'self'` CSP blocks). The CLI's refusal said "the browser can read it with OCR", sending a reader with a scanned signed copy to a surface that cannot read it either; the public `/known-limits` page said scanned pages "are read by OCR … in the browser only". Both now say no surface runs OCR and to OCR the scan first, the page's unused OCR page cap is gone from its data, and a test holds the refusal message to that. The confidence join stays open until OCR can run from same-origin assets, which is a privacy-posture decision for the owner, not a build task.

## Progress — 9.978.0

Task 6: the comparison Word report opens with "Signed copy against the final" (the verdict, "text conformity only, not valid execution", the hash, the differences, and what was set aside) whenever a conformity is passed, which `compare --executed --format docx` now does. The tab's result offers "Check a signed copy against this final…": `runExecutedComparison` analyzes the signed copy and holds it to the final's type only when routing moved, as `compareExecuted` does, and refuses an empty text layer with the same message. The comparison page shows the verdict line, and its JSON carries `conformity` as the CLI's does. The cross-surface test checks both run hashes, the comparison hash and the `conformity_hash` against `compareExecuted`; an e2e drives it in the tab at phone width. Task 8: the `reference.md` row names the tab; `/known-limits` now says no surface reads a scan (9.977.0). Open: task 1's PDF fixtures and task 4 (blocked on OCR).
