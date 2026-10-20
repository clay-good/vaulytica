# Tasks

- [ ] 1. Fixtures first: a PDF with a black rect over text (post-text paint order), one with the rect painted before the text, one with an unapplied `/Redact` annotation, one with a `Square` annotation with interior color, one image-only scan; a DOCX with black-on-black highlight, white-on-white, run shading, and a theme-color run without a theme part. Each fixture's hidden string is a sentinel no other fixture uses, so the masking grep is unambiguous.
- [ ] 2. `src/delivery/container.ts`: PDF operator walk (CTM, fill color, pending path, paint order) producing `RedactionFact[]`; bound the walk and report `inspectable: false` per page past it. Measure cost over the PDF specimens before choosing the bound.
- [x] 3. `src/delivery/container.ts`: DOCX run-property read for color/highlight/shading with the Word highlight-name table and theme resolution; `inspectable: false` for unresolved theme colors.
- [x] 4. `src/delivery/types.ts` `RedactionFact`; `src/delivery/handoff.ts` `HANDOFF-006`, `HANDOFF-007`, `HANDOFF-008` with messages, severities (006 and 007 critical, 008 warning), and citations (the container element; 17 C.F.R. § 229.601(b)(10)(iv) for 008, with `retrieved_at`).
- [x] 5. `HANDOFF-008` scope: the SEC-exhibit family list (derived from the EDGAR sample's accepted routes) and the `--sec-exhibit` assertion registered in `REGISTERED_ASSERTION_GATES`; legend-element detection on the first page.
- [x] 6. Masking: extend the masking assertions in `src/delivery/delivery.test.ts` to grep every serialized export for every fixture's sentinel; the masked shape is the only representation.
- [x] 7. Renderers and reach: tab card, CLI summary and `--fail-on-delivery`, JSON, DOCX, HTML, SARIF, bundle card; MCP `analyze_document` `include: ["delivery"]` (new); write a delivery reach test over those surfaces (break it on purpose once) and add the rules to `honesty-caveat-reach.test.ts`'s list.
- [x] 8. Narrow the production-QA scope statement to "image-layer redactions and OCR'd scans are not checked"; add a `known-limits` ledger entry for the image-only class with a plain sentence.
- [ ] 9. Docs: `reference.md` delivery table rows for 006–008, `threat-model.md` one paragraph, site "Clean to send" copy; the `/known-limits` page regenerates and its guard passes.
- [ ] 10. Full gate green: typecheck, lint, format:check, tests, build, the privacy e2e, and the delivery format-invariance relation re-run with the new fixtures.

## Progress — 9.955.0 (slice A)

Built: the DOCX read and `HANDOFF-007` (black/white-on-same, run and paragraph shading; `auto` text is white only on dark SHADING, never on a highlight); `HANDOFF-006` for an unapplied `/Redact` annotation read from the uncompressed bytes; `HANDOFF-008` with its scope (`SEC_EXHIBIT_FAMILIES`, held equal to the routing labels, and `--sec-exhibit`, registered); masking asserted by sentinel grep; the production-QA scope statement narrowed. `redactions` is optional and absent when empty, so no existing `delivery_hash` moves.

Not yet built, and stated where the result is shown:
- Task 1–2: the PDF operator walk (a filled rectangle painted over text, a `Square` annotation with interior color) and its fixtures.
- Task 3: a theme color is read through `w:val` only; `w:themeColor` without one is not resolved.
- Task 8: a known-limits ledger row for the image-only class (the ledger holds specimen-measured debts; this class has none yet).
- Task 9: site "Clean to send" copy.

## Progress — 9.974.0

Task 7: `tests/integration/delivery-reach.test.ts` drives one black-highlight DOCX through the CLI's JSON, HTML, SARIF and Word report, the terminal summary, `--fail-on-delivery` (exit 2), the tab's result, delivery card and page, and a folder's page, and asserts `HANDOFF-007` is on each and the covered words are on none. Broken on purpose once: dropping the id from the page's delivery rows turned the tab and folder cases red. The MCP surface is asserted in `tools/mcp/tools.test.ts`. The rules were not added to `honesty-caveat-reach.test.ts`: that list is of render surfaces, not rule ids, and every surface above is already on it.
