# Design — redaction integrity

## What a liftable redaction looks like in the bytes

| Carrier | What the author did | What is in the file | Signal |
|---|---|---|---|
| PDF | drew a filled rectangle (Acrobat "Rectangle" tool, Preview, Word shapes) over text, then flattened or not | content stream: `re` + `f`/`f*` with a fill color set; text items (`Tj`/`TJ`) at the same coordinates | a filled, single-color rect whose bbox overlaps text-item bboxes |
| PDF | applied Acrobat "Mark for redaction" and did not click "Apply" | a `/Redact` annotation; text untouched | annotation subtype `Redact` present at all |
| PDF | `Square` annotation with interior color | annotation `/Subtype /Square` with `/IC` | overlap test as for rects |
| PDF | black highlight in Word, saved as PDF | Word emits the highlight as a filled rect behind the glyphs | same as row 1 |
| DOCX | black highlight on black text | `w:highlight w:val="black"` with no `w:color` or `w:color w:val="000000"` | color = highlight |
| DOCX | white font on white | `w:color w:val="FFFFFF"` | color = page/shading background |
| DOCX | paragraph or run shading | `w:shd w:fill="000000"` over a run with dark text | fill = color |
| scan | black box drawn on an image | nothing in the text layer | **not detectable here**; recorded as a known limit |

## Reading the PDF

`src/ingest/pdf.ts` already walks every page with `getTextContent()` and keeps each item's `transform` (position and font size) and `width`. The delivery read adds `page.getOperatorList()` on the same `PDFPageProxy` and walks `fnArray`/`argsArray` once, tracking:

- the current transformation matrix (`OPS.transform`, `save`, `restore`),
- the current fill color (`setFillRGBColor`, `setFillGray`, `setFillCMYKColor`, `setFillColorN`),
- the pending path (`rectangle`, `moveTo`/`lineTo` sequences that close an axis-aligned quadrilateral),
- a paint (`fill`, `eoFill`, `fillStroke`), at which point each pending rect becomes a candidate.

A candidate rect that covers one or more text-item bboxes by more than half of each item's area, and whose fill is opaque (no `setGState` alpha below 1 in force), is a `RedactionFact { page, bbox, covered_items, masked_shape }`. `masked_shape` is the covered text with every letter replaced by `x`, every digit by `#`, whitespace kept, so a reviewer can see "a 9-digit number" or "two words" without the engine reproducing the hidden content. The excerpt is never the text; the masking assertions in `src/delivery/delivery.test.ts` extend to it.

**Z-order is not consulted.** A rect painted *before* the text is a background box, not a redaction, and would be a false positive. The operator walk records the index at which each text item is painted (`showText` ops carry the same order as `getTextContent` items, as pdf.js derives one from the other); a rect counts only if its paint index is later than every covered item's. This is the rule `x-ray` approximates by rendering and checking the pixels are one color; here the order is read directly, which is cheaper and deterministic.

**Bound.** Pages past the existing page cap are not walked; the fact says `pages_scanned`. An operator list over 250,000 ops on one page stops and reports `inspectable: false` for that page with the reason, the same shape `MAX_COUNT` gives the DOCX revision counter.

## Reading the DOCX

`src/ingest/docx-notices.ts` already inflates `word/document.xml` and counts `w:vanish`. The same pass reads each `w:r`'s `w:rPr` for `w:color`, `w:highlight`, `w:shd`, and the enclosing `w:pPr`'s `w:shd`, and compares:

- `color == highlight` (named highlight colors map to hex through Word's fixed table),
- `color == shd.fill`,
- `color == "FFFFFF"` with no shading (white on the page).

`w:color w:val="auto"` is black unless shading is dark, and is treated as black. A theme color (`w:themeColor`) is resolved through `word/theme/theme1.xml` when present, else the run is reported as `inspectable: false` for this check with the reason, never guessed.

## The declared-redaction legend (HANDOFF-008)

Three patterns in the flattened text: `[***]` and its longer runs, `[REDACTED]`, `[OMITTED]`, `[Information omitted]`, `***` alone on a line. When any appears and the document is in scope, the first-page text (the first 3,000 characters of the tree, or the first page of a PDF) is searched for the legend's required elements: the word *omitted* or *excluded* or *redacted*, and the phrase *not material* (or *immaterial*), and one of *customarily and actually treats as private or confidential* / *competitive harm* (the pre-2021 standard, still on many older exhibits). A legend missing any element is reported as "omission markers present; first-page statement not found or incomplete", citing 17 C.F.R. § 229.601(b)(10)(iv) and listing the elements found. Nothing is said about whether the omitted information was material. That is the registrant's judgment.

Scope: SEC-exhibit families (the ones the EDGAR sample routes to) or `--sec-exhibit`. Outside that scope the markers are reported under the existing placeholder rule only, as today.

## Hash and churn

`RedactionFact[]` joins `ContainerFacts`; `delivery_hash` covers it. Documents with no redaction facts produce the byte-identical delivery report they produce today, because the array is empty and the renderers gate on presence. Every existing delivery golden is unchanged; the new fixtures are the ones that move.
