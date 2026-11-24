# Tasks

- [~] 1. Fixtures: a final DOCX and (a) a text-layer PDF of its executed form with filled blocks and dates, (b) the same with one changed figure, (c) the same with an added signatory, (d) an image-only scan with a seeded low-confidence word; a two-folder closing set with one unpaired file and one title tie.
- [x] 2. `src/report/conformity.ts`: allowance classifier over paragraphs (signature window reuse, blank-to-date fill, initials, cover pages, furniture, watermark words); verdict; canonical table and `conformity_hash`.
- [x] 3. `clause-diff.ts`: accept an allowance predicate so set-aside paragraphs are listed, not diffed; the plain comparison path unchanged (goldens hold).
- [x] 4. OCR confidence join: unverified differences and the could-not-determine verdict in the browser; CLI refusal for image-only PDFs. **The verdict (9.1009.0) and the WORD-level unverified-differences join (9.1014.0) are both built; neither needed OCR to run** — see the notes at the end.
- [x] 5. `compare --executed` and `--executed-set` with `--fail-on-nonconformity`; title pairing via the matcher; stream contract respected.
- [x] 6. Renderers: Markdown, JSON, DOCX section; browser affordance and Word deliverable; cross-surface hash parity on text-layer inputs.
- [x] 7. Metamorphic relations: filling blanks in the final must not change the verdict; altering any non-allowance paragraph must; format transforms on the executed side must not.
- [x] 8. Docs: `reference.md` comparison section, `ci-integration.md` closing-set example; `/known-limits` sentence for image-only scans headless.
- [x] 9. Full gate green.

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

## Progress — 9.980.0

Task 1, the text-layer half: `executed-cross-format.test.ts` checks a Word final against a PDF signed copy (clean, a changed figure, an added signatory, a changed title) and holds the relation over every fourth specimen. Its first run found that a change of FORMAT read as a difference: 17 of 31 specimens were "not identical" with nothing executed. Three causes, each fixed in `checkConformity` (version 2):
- A line one ingest reads as a heading and the other as a paragraph (a Word Title paragraph, a 16-point PDF line) is the same line; it is set aside as "a heading in the other file". Headings are now compared too, so a title the signed copy changed is caught (the paragraph diff never saw headings).
- A PDF joins a short line to the next where Word keeps two paragraphs. A changed line that is its old self followed, word for word, by the lines after it is a join, set aside as "the same words, split into paragraphs differently"; so is a set of differences whose word streams, in document order, are equal. A moved paragraph or a changed word still counts.
- The signature-block count read only lines that START with "By:"; a joined "… By: /s/ …" is now counted.
Measured: 83 of 91 identical, every one of 52 changed figures caught. The eight that still differ are declared in the test with reasons, and the test fails if any becomes identical. Five are the test renderer setting an all-caps line past the page edge (pdf.js drops the glyph, so the PDF really lacks it). Three are joins that cross an execution line, reported rather than reconciled. Open: the image-only scan fixture (task 1's last item) and task 4.

## Progress — 9.1002.0 (the Action reaches it)

Part of task 5. `compare --executed` and `--executed-set` shipped at 9.968.0
and 9.977.0 on the CLI, the MCP server and the tab, and had no CI path at all:
`action.yml` declared neither mode nor the `--fail-on-nonconformity` gate, so
the check written for the closing table could not run in a workflow. Now four
inputs — `executed`, `executed-set`, `fail-on-nonconformity`, and
`confirm-pairing` beside them — with the Action refusing, by input name, what
the CLI refuses by flag: both modes at once, the gate without a mode, and the
three inputs `--executed-set` sets aside. `docs/ci-integration.md` carries a
closing-set workflow. `tests/integration/action-flag-coverage.test.ts` fails
the build if a later compare flag ships with no input.

## Progress — 9.1005.0 (task 1 all but the scan; task 9)

Task 1 is complete except (d), the image-only scan with a seeded low-confidence
word, which is blocked with task 4: no surface runs OCR. Built and standing:
the final DOCX against a text-layer PDF of its executed form (a), the same with
one changed figure (b) and with an added signatory (c) in
`executed-cross-format.test.ts`, and the two-folder closing set with an
unpaired file and a title tie in `compare-executed-set.test.ts` ("pairs by
title, lists the unpaired, and refuses to choose between a tie"). Task 9: the
full gate is green at 9.1005.0.

## Why task 4 is blocked — verified 9.1008.0, replacing a vague claim

The note used to read "no surface runs OCR", which is true in effect and
useless as a reason, so it was re-tested. What is actually there:

- The OCR path **exists and is called**: `src/ingest/pdf.ts` imports and runs
  `runOcr` when the text layer is thin and `options.allowOcr` is set.
- The confidence machinery **exists too**: `ocr.ts` exports
  `OCR_CONFIDENCE_THRESHOLD = 60` and `markLowConfidence`, OCR output marks
  each low-confidence word `[uncertain]`, and `pdf.ts` counts them and raises a
  run warning naming the count and telling the reader to verify any party
  name, amount or date near a marker.

So the blocker is neither the OCR nor the confidence data. It is this:

1. **Every shipped surface passes `allowOcr: false`** — `src/ui/pipeline.ts`
   at lines 621 and 1583, both call sites. Nothing can reach the OCR path as
   the product ships.
2. **Turning it on is a held maintainer decision**, not an oversight: the
   tesseract `eng` language model is fetched over the network, which the
   product's "nothing leaves the tab, no server" guarantee forbids, and the
   path cannot be verified headless or in a sandbox. `tesseract.js` is pinned
   at 5 for the same reason.
3. **`Conformity.verdict` is `"identical" | "differences"`** with no third
   state, so there is nowhere to put an unverified difference. Adding a
   `could-not-determine` state now would be a branch no input can reach — the
   dead-detector class this repository has been bitten by before — so it waits
   for the OCR input rather than landing ahead of it.

The honest summary: this task needs a product decision about shipping a
network-fetched OCR model, not more code.

## Progress — 9.1009.0 (the verdict is built; only the word-level join waits)

The blocked note conflated two different things, and splitting them made most
of this task buildable today.

- **Word-level** confidence is what OCR gives: which words it may have misread.
  That is still unavailable, for the reason recorded above.
- **Document-level** completeness is a different and coarser question — *was
  the signed copy's text extracted in full?* — and the ingest has always
  answered it. `assessTextLayer` already detects a scan whose text layer covers
  only some pages.

The verdict turns on the second, not the first. So it is built:

`Conformity.verdict` gains **`could-not-determine`**, with
`unverified_reason`. 🚨 It exists because the other two verdicts were both
false on a partially-read document: `differences` asserts differences the
comparison cannot substantiate, and `identical` is a clean bill of health for
pages nobody read. The second is the more dangerous, which is why an
incomplete read disqualifies **both** ordinary verdicts and not merely the
negative one.

`src/report/_incomplete-text.ts` derives the reason from the ingest's warning
CODES rather than its prose, and both call sites pass it — `tools/cli/api.ts`
for `compare --executed` and `src/ui/main.ts` for the tab.

Found on the way, and fixed:

- **A mislabelled warning code.** The sentence explaining that OCR was
  *unavailable* contains the word "OCR", so `codeOf`'s `/\bOCR\b/` returned
  `"ocr"` — "a scan that was read through OCR" — for a file where OCR never ran
  and most pages yielded nothing. A caveat about accuracy stood in for a fact
  about coverage, and anything sorting on these codes under-reported it. New
  code `partial-text-layer`, matched before the generic test, in the same sets
  `ocr` was in so the triage tier is unchanged. Proven reachable from a real
  four-page PDF (`mixedLayerPdf`), not assumed — `scannedPdf()` cannot stand in,
  because `assessTextLayer` exempts a single-page document.
- **The gate's message was a false statement.** `--fail-on-nonconformity`
  printed "the signed copy differs from the final" for every non-identical
  verdict. For `could-not-determine` that asserts a difference where the truth
  is that no comparison was possible; the gate exists to stop a false clear,
  not to manufacture a difference. It now says which it is. (The gate itself
  needed no change: it passes only on `identical`, so an unknown already
  tripped it — a gate that passes on "unknown" would be a false green.)

No existing `conformity_hash` moves: the new field is spread into the canonical
object only when set, and a test asserts a complete-text run hashes exactly as
before.

**What is left of task 4** is the word-level join: marking an individual
difference unverified because it sits near an `[uncertain]` OCR marker. That
needs OCR actually running, which needs the product decision recorded above.

## Progress — 9.1014.0 (the word-level join, which also needed no OCR)

⚠️ **I recorded this half as needing "OCR actually running". Wrong, in exactly
the way the verdict half was wrong.** OCR is needed to PRODUCE the markers in
the wild — but `markLowConfidence` writes them into the text as
`word [uncertain]`, so by the time a comparison sees them they are ordinary
words. The join acts on text, and text is something a test can write.

**Why it is worth having on top of the document-level verdict.** The verdict
says no conclusion is possible about the document. That is true and it is also
unhelpful on its own: it tells an attorney to re-read everything. In an OCR'd
signed copy, a difference whose text carries an `[uncertain]` marker may be the
scanner misreading a word, while a difference with no marker near it is a real
difference even so. `unverified_differences` names the first kind, with the
words OCR doubted, and `conformityLine` ends with "check those by eye first".

Deliberately NOT hashed: the list is derived entirely from the text of the
differences the canonical object already covers, so hashing it would add
nothing and would move every existing `conformity_hash` for an OCR'd pair. Same
reasoning as the `DDL-*` notes sitting outside their register's hash. A test
pins that the hash is stable across repeated runs and still responds to the
reason string.

**What is genuinely left on this change is task 1(d) alone**: an image-only
scan with a seeded low-confidence word. The fixture the JOIN needs — text
carrying markers — is built and tested. A fixture that makes OCR itself emit a
marker needs OCR to run, which needs the product decision recorded above about
shipping a network-fetched language model against the no-server guarantee.
