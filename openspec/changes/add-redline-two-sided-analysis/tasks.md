# Tasks

- [ ] 1. Fixtures: a DOCX redline with insertions, deletions, a move, a formatting-only change, and a table-cell change; plus Word's Accept-All and Reject-All exports of it, committed, for the round-trip test.
- [ ] 2. `src/ingest/docx-revisions.ts`: the linear OOXML rewrite producing the rejected `document.xml`; property test that accepted(rewrite) and rejected(rewrite) each contain no revision elements; bounded matching per `container.ts`.
- [ ] 3. `ingestDocxBuffer(buf, { revisions })` and the `ingestDocx` wrapper with the `#rejected` / `#accepted` name suffix; the default path byte-identical (corpus goldens unchanged).
- [ ] 4. `tools/cli/api.ts` `compareRedline(path, opts)` over `compareFiles` with `pinType`; `compare --redline`; the no-tracked-changes refusal; `MAX_COUNT` notice carried.
- [ ] 5. Attribution: `collectRevisions` with spans; overlap join; `revision_authors` on the comparison's introduced/resolved entries; author column in `compare-docx.ts`; Markdown summary column.
- [ ] 6. Browser: the comparison affordance on a result whose ingest notice reports tracked changes; the Word deliverable; hashes identical to the CLI on the same bytes (cross-surface parity test extended).
- [ ] 7. MCP `compare_documents` `redline_path`; Action `redline` input; `ci-integration.md` example "gate a counterparty redline on a pull request".
- [ ] 8. Format-invariance relation for the rejected reading (same five transforms); reach and honesty-caveat tests extended.
- [ ] 9. Docs: `reference.md` ingest table row for redlines updated to say both readings are available; the "About this input" notice links to the comparison.
- [ ] 10. Full gate green.
