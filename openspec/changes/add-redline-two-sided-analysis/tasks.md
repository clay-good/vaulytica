# Tasks

- [ ] 1. Fixtures: a DOCX redline with insertions, deletions, a move, a formatting-only change, and a table-cell change; plus Word's Accept-All and Reject-All exports of it, committed, for the round-trip test.
- [x] 2. `src/ingest/docx-revisions.ts`: the linear OOXML rewrite producing the rejected `document.xml`; property test that accepted(rewrite) and rejected(rewrite) each contain no revision elements; bounded matching per `container.ts`.
- [x] 3. `ingestDocxBuffer(buf, { revisions })` and the `ingestDocx` wrapper with the `#rejected` / `#accepted` name suffix; the default path byte-identical (corpus goldens unchanged).
- [x] 4. `tools/cli/api.ts` `compareRedline(path, opts)` over `compareFiles` with `pinType`; `compare --redline`; the no-tracked-changes refusal; `MAX_COUNT` notice carried.
- [x] 5. Attribution: `collectRevisions` with spans; overlap join; `revision_authors` on the comparison's introduced/resolved entries; author column in `compare-docx.ts`; Markdown summary column.
- [x] 6. Browser: the comparison affordance on a result whose ingest notice reports tracked changes; the Word deliverable; hashes identical to the CLI on the same bytes (cross-surface parity test extended).
- [x] 7. MCP `compare_documents` `redline_path`; Action `redline` input; `ci-integration.md` example "gate a counterparty redline on a pull request".
- [ ] 8. Format-invariance relation for the rejected reading (same five transforms); reach and honesty-caveat tests extended.
- [x] 9. Docs: `reference.md` ingest table row for redlines updated to say both readings are available; the "About this input" notice links to the comparison.
- [ ] 10. Full gate green.

## Progress

- 9.965.0 shipped slice A: tasks 2–4, and the MCP half of task 7 (`redline_path`).
  - The fixture is built in code (`redlineDocx()` in `src/delivery/_fixtures.ts`): an insertion, deletions, a move and a paragraph-mark insertion. Word's Accept-All and Reject-All exports of it (task 1's round-trip) need Word and are not committed yet.
  - The rewrite is `indexOf`-based. A malformed part stays linear: an unclosed element ends the scan rather than being searched for again.
  - The CLI refuses a file with no tracked changes, and a file that is not a DOCX.
- 9.966.0 shipped task 5. Attribution is by text containment: a finding names the authors of the insertions (introduced) or deletions (resolved) its quoted paragraph contains. An absence finding names no one. Changes under 12 characters are not used. The comparison DOCX lists authors per finding rather than in a table column, because the report renders findings as blocks, not a table.
- 9.967.0 finished task 7 (the Action `redline` input and the `ci-integration.md` example). Toward task 8, it added a different relation from the one the task names: every run of eight specimens is marked deleted or inserted, and the rejected or accepted reading must then report the plain DOCX's findings. A mutation of the rewrite fails all eight. The five format transforms over a redline are still open.
- 9.973.0 shipped tasks 6 and 9. A DOCX with tracked changes shows "Compare both sides of this redline" beside "Compare a revised version…"; it runs `runRedlineComparison` (the CLI's `compareRedline`: the same `#rejected` / `#accepted` names, the accepted reading held to the rejected reading's type) and renders the comparison page the two-file compare renders. The Word report and the JSON carry `revision_authors`. `prepareDocument` gained an optional reading (`revisions`, a pinned `playbook_id`), as `runIngested` takes them. The cross-surface test checks both runs' hashes, the comparison hash and the attribution against the CLI; an e2e drives the tab and reads the author from the downloaded JSON. The accepted reading's notice now names both ways to compare. The page itself does not show authors; they are in the downloads.
- Open: task 1's Word round-trip (needs Word); task 8's five transforms.
