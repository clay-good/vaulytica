# Tasks

- [x] 1. Fixtures first: a PDF with a black rect over text (post-text paint order), one with the rect painted before the text, one with an unapplied `/Redact` annotation, one with a `Square` annotation with interior color, one image-only scan; a DOCX with black-on-black highlight, white-on-white, run shading, and a theme-color run without a theme part. Each fixture's hidden string is a sentinel no other fixture uses, so the masking grep is unambiguous.
- [x] 2. `src/delivery/container.ts`: PDF operator walk (CTM, fill color, pending path, paint order) producing `RedactionFact[]`; bound the walk and report `inspectable: false` per page past it. Measure cost over the PDF specimens before choosing the bound.
- [x] 3. `src/delivery/container.ts`: DOCX run-property read for color/highlight/shading with the Word highlight-name table and theme resolution; `inspectable: false` for unresolved theme colors.
- [x] 4. `src/delivery/types.ts` `RedactionFact`; `src/delivery/handoff.ts` `HANDOFF-006`, `HANDOFF-007`, `HANDOFF-008` with messages, severities (006 and 007 critical, 008 warning), and citations (the container element; 17 C.F.R. § 229.601(b)(10)(iv) for 008, with `retrieved_at`).
- [x] 5. `HANDOFF-008` scope: the SEC-exhibit family list (derived from the EDGAR sample's accepted routes) and the `--sec-exhibit` assertion registered in `REGISTERED_ASSERTION_GATES`; legend-element detection on the first page.
- [x] 6. Masking: extend the masking assertions in `src/delivery/delivery.test.ts` to grep every serialized export for every fixture's sentinel; the masked shape is the only representation.
- [x] 7. Renderers and reach: tab card, CLI summary and `--fail-on-delivery`, JSON, DOCX, HTML, SARIF, bundle card; MCP `analyze_document` `include: ["delivery"]` (new); write a delivery reach test over those surfaces (break it on purpose once) and add the rules to `honesty-caveat-reach.test.ts`'s list.
- [x] 8. Narrow the production-QA scope statement to "image-layer redactions and OCR'd scans are not checked"; add a `known-limits` ledger entry for the image-only class with a plain sentence.
- [x] 9. Docs: `reference.md` delivery table rows for 006–008, `threat-model.md` one paragraph, site "Clean to send" copy; the `/known-limits` page regenerates and its guard passes.
- [x] 10. Full gate green: typecheck, lint, format:check, tests, build, the privacy e2e, and the delivery format-invariance relation re-run with the new fixtures.

## Progress — 9.955.0 (slice A)

Built: the DOCX read and `HANDOFF-007` (black/white-on-same, run and paragraph shading; `auto` text is white only on dark SHADING, never on a highlight); `HANDOFF-006` for an unapplied `/Redact` annotation read from the uncompressed bytes; `HANDOFF-008` with its scope (`SEC_EXHIBIT_FAMILIES`, held equal to the routing labels, and `--sec-exhibit`, registered); masking asserted by sentinel grep; the production-QA scope statement narrowed. `redactions` is optional and absent when empty, so no existing `delivery_hash` moves.

Not yet built, and stated where the result is shown:
- Task 8: a known-limits ledger row for the image-only class (the ledger holds specimen-measured debts; this class has none yet).

## Progress — 9.974.0

Task 7: `tests/integration/delivery-reach.test.ts` drives one black-highlight DOCX through the CLI's JSON, HTML, SARIF and Word report, the terminal summary, `--fail-on-delivery` (exit 2), the tab's result, delivery card and page, and a folder's page, and asserts `HANDOFF-007` is on each and the covered words are on none. Broken on purpose once: dropping the id from the page's delivery rows turned the tab and folder cases red. The MCP surface is asserted in `tools/mcp/tools.test.ts`. The rules were not added to `honesty-caveat-reach.test.ts`: that list is of render surfaces, not rule ids, and every surface above is already on it.

## Progress — 9.975.0

Task 2, built in `src/delivery/pdf-paint.ts` rather than `container.ts`, because it needs pdf.js and the container read is synchronous byte work. `boxesOverText` is pure over an operator list: it tracks the transformation matrix (and form and annotation matrices), the text state (matrix, leading, font size, char and word spacing, horizontal scale, rise, TJ kerning), the fill (solid or not), its alpha and blend mode, and places every glyph's centre. An opaque, solid, unblended, axis-aligned filled rectangle covers the glyphs painted BEFORE it whose centres it contains; a box painted first is a background, and text painted after a box shows over it. A `Square` annotation is read from the appearance pdf.js draws for it after the content; every other annotation is skipped by id (a highlight blends; `/Redact` is the annotation reader's). Both filters were removed once each and the tests went red. Facts join `HANDOFF-006` as `pdf-filled-box`, masked; they are added only when found, so no other report's `delivery_hash` moves. A file pdf.js cannot open, a page over 250,000 operations and pages past 500 are named in the note.

Cost, measured on a 30-page text PDF under load: 65–75 ms for the walk against 170–310 ms for the PDF ingest. The fixtures (task 1) are PDFs built in code in `pdf-paint.test.ts`: box after text, box before text, white text on a dark bar, translucent and Multiply fills, a box beside the text, a scaled page, TJ kerning, a Square, a Highlight, a `/Redact`, and bytes pdf.js cannot open. Not built: the image-only scan fixture.

## Progress — 9.976.0

Task 3's theme half: `w:themeColor` and `w:themeFill` are resolved through `word/theme/theme1.xml`'s color scheme (a system color by its saved `lastClr`), and the theme value wins over the stated hex when both are present, because that is what Word paints. A tinted or shaded theme color (`w:themeTint`/`w:themeShade`, `w:themeFillTint`/`w:themeFillShade`) falls back to the stated hex; with no hex and no resolution the run is counted, not checked, and the scan's note says how many ("N runs use theme colors the file's theme does not resolve"). Tested: white-on-white as `background1` with no hex, `text1` on `text1` shading, the theme beating a stated black, a tinted color and a missing theme (both named in the note, neither guessed), and an ordinary accent-colored heading (nothing).

Task 9 (after 9.978.0): the landing page's "What it checks in every document" gains a "Before you send it" card naming the pre-disclosure scan, the three liftable-redaction kinds included, and saying the covered words are never shown. The `reference.md` rows and the threat-model paragraph were updated with tasks 2 and 3. 

## Progress — 9.979.0

Task 10. The delivery format-invariance relation over the redaction fixtures (`pdf-paint.test.ts`): the same box over the same words is found however the page writes them (one `Tj`, a `TJ` array, a `Tm` text matrix, one show per word, a translated page, a form XObject). It found a real defect at once: pdf.js 6 passes `setTextMatrix` and form matrices as ONE typed array, so text placed with `Tm` or drawn inside a form was never positioned. Fixed with one `matrixOf` reader; reverting it fails both cases.

The privacy e2e (`privacy-interception.spec.ts`) drops a PDF with a box over its text in the real tab: the page says "A redaction can be lifted", the covered words appear nowhere in it, and every request is a same-origin GET. It found a second, older defect: in the tab, pdf.js's worker DETACHED the PDF's buffer during ingest, and `prepareDocument` hands that same buffer to the pre-disclosure scan, so the tab scanned zero bytes for every PDF: no metadata, comments, unapplied redaction marks or boxes, on any PDF, since the scan shipped. The CLI copies its buffers and was unaffected. `ingestPdfBuffer` now gives pdf.js a copy; a unit test fails without it.

## Progress — 9.981.0 (complete)

Task 1's last fixture: an image-only page (an inline image, a black box in pixels) is walked, yields no fact and no `HANDOFF-006`. The production-QA scope statement named "a box drawn over a PDF's text layer" as NOT checked, which stopped being true at 9.975.0; it now lists the three shapes checked (Word color, theme color included; an unapplied PDF redaction mark; a filled box or square annotation over PDF text) and the ones that are not (a redaction burned into an image, an OCR'd scan, a pattern, translucent or blended fill). Every task is built.
