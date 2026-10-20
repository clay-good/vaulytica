# Tasks

- [ ] 1. Fixtures: a DOCX redline with insertions, deletions, a move, a formatting-only change, and a table-cell change; plus Word's Accept-All and Reject-All exports of it, committed, for the round-trip test.
- [x] 2. `src/ingest/docx-revisions.ts`: the linear OOXML rewrite producing the rejected `document.xml`; property test that accepted(rewrite) and rejected(rewrite) each contain no revision elements; bounded matching per `container.ts`.
- [x] 3. `ingestDocxBuffer(buf, { revisions })` and the `ingestDocx` wrapper with the `#rejected` / `#accepted` name suffix; the default path byte-identical (corpus goldens unchanged).
- [x] 4. `tools/cli/api.ts` `compareRedline(path, opts)` over `compareFiles` with `pinType`; `compare --redline`; the no-tracked-changes refusal; `MAX_COUNT` notice carried.
- [ ] 5. Attribution: `collectRevisions` with spans; overlap join; `revision_authors` on the comparison's introduced/resolved entries; author column in `compare-docx.ts`; Markdown summary column.
- [ ] 6. Browser: the comparison affordance on a result whose ingest notice reports tracked changes; the Word deliverable; hashes identical to the CLI on the same bytes (cross-surface parity test extended).
- [ ] 7. MCP `compare_documents` `redline_path`; Action `redline` input; `ci-integration.md` example "gate a counterparty redline on a pull request".
- [ ] 8. Format-invariance relation for the rejected reading (same five transforms); reach and honesty-caveat tests extended.
- [ ] 9. Docs: `reference.md` ingest table row for redlines updated to say both readings are available; the "About this input" notice links to the comparison.
- [ ] 10. Full gate green.

## Progress

- 9.965.0 shipped slice A: tasks 2–4, and the MCP half of task 7 (`redline_path`).
  - The fixture is built in code (`redlineDocx()` in `src/delivery/_fixtures.ts`): an insertion, deletions, a move and a paragraph-mark insertion. Word's Accept-All and Reject-All exports of it (task 1's round-trip) need Word and are not committed yet.
  - The rewrite is `indexOf`-based. A malformed part stays linear: an unclosed element ends the scan rather than being searched for again.
  - The CLI refuses a file with no tracked changes, and a file that is not a DOCX.
- Open: task 1's Word round-trip; task 5 (author attribution); task 6 (browser); the Action `redline` input and the `ci-integration.md` example (rest of task 7); task 8 (format-invariance for the rejected reading); task 9's notice link.
