# Design notes

## Container strategy

Reuse the v9 approach: unzip the original container with fflate, touch only the
parts a comment requires, rezip deterministically (fixed mtimes, stable entry
order — mirror how the DOCX report writer already achieves byte-stable output):

- `word/comments.xml` — one `w:comment` per finding (id = finding index in the
  report's stable order; author `Vaulytica <ENGINE_VERSION>`; initials `VA`;
  `w:date` fixed to the epoch sentinel the report already uses for
  determinism).
- `word/document.xml` — insert `w:commentRangeStart`/`End` +
  `w:commentReference` around the anchor run(s). Never insert, delete, or
  reorder any text node.
- `[Content_Types].xml` + `word/_rels/document.xml.rels` — register the
  comments part if absent.

## Anchoring

The engine's excerpt carries `section_id` + `start_offset`/`end_offset` into
the flattened text. Map back to `document.xml` by walking the same
paragraph/run order mammoth flattened (the DocumentTree preserves it). The
mapping is a pure function; property-test it by round-tripping: extract text
from the annotated docx and confirm the commented span equals the finding's
excerpt text.

Failure mode: offset not locatable (e.g., OCR'd PDF → DOCX mismatch is
impossible here since export is DOCX-in/DOCX-out, but tracked-changes-heavy
files can shift runs). Those findings aggregate into one comment anchored on
the first paragraph titled "Findings without a locatable anchor (N)". Count
must equal total findings minus anchored findings — asserted in tests.

## Invariants (tests)

1. Body byte-parity: unzip original and annotated; every part except
   `comments.xml`, `document.xml` (comment markup only), `.rels`,
   `[Content_Types].xml` is byte-identical; `document.xml` text content
   (comment elements stripped) is byte-identical to the original's.
2. Determinism: two runs → byte-identical output file.
3. Lint-not-draft: no `w:ins`/`w:del` elements are ever written.
4. Masking: HANDOFF-005 comment text uses the masked value (grep the part).
5. A tracked-changes-laden original (the v9 fixture) round-trips without
   corrupting existing revisions.
