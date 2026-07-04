# Tasks

- [x] 1. Reproduce as failing tests: a preamble-bearing DOCX and PDF fixture
  each assert the preamble text is present in the flattened tree and
  `word_count` (fails today). *(Reproduced through the real CLI on a crafted
  preamble DOCX: pre-fix `word_count: 8` — the 23-word preamble containing
  "unlimited liability and waives all warranties" silently deleted; post-fix
  `word_count: 31`.)*
- [x] 2. Fix `src/ingest/docx.ts` and `src/ingest/pdf.ts`: replace the
  `!promoted && sections.length > 1` root-drop with the paste-path guard
  (`sections[0] === root && root.paragraphs.length === 0`).
- [x] 3. Add `src/ingest/ingest-fidelity.test.ts`: one preamble document
  through docx/pdf/paste paths; full text survives each. *(Plus an
  empty-root case pinning that the legitimate drop still happens. PDF
  fixture note: pdfjs discards glyphs positioned past the MediaBox edge, so
  the fixture's preamble spans two page-fitting lines.)*
- [x] 4. Add the text-conservation property test (fast-check) over generated
  section mixes. *(100 runs over generated heading/paragraph mixes through
  `parseDocxHtml`: no paragraph text is ever lost to restructuring.)*
- [x] 5. Re-baseline goldens whose fixtures carry pre-heading content; record
  in the change log that prior hashes attested truncated scans.
  *(Zero goldens changed: every committed DOCX/PDF fixture begins with a
  heading — which is exactly why the truncation shipped unnoticed. No prior
  committed hash attested a truncated scan; the new fidelity tests are the
  first fixtures with pre-heading content.)*
- [x] 6. Full gate green. *(typecheck, lint, format:check, 3,681 tests / 261
  files, build.)*
