# Tasks

- [ ] 1. Reproduce as failing tests: a preamble-bearing DOCX and PDF fixture
  each assert the preamble text is present in the flattened tree and
  `word_count` (fails today).
- [ ] 2. Fix `src/ingest/docx.ts` and `src/ingest/pdf.ts`: replace the
  `!promoted && sections.length > 1` root-drop with the paste-path guard
  (`sections[0] === root && root.paragraphs.length === 0`).
- [ ] 3. Add `src/ingest/ingest-fidelity.test.ts`: one preamble document
  through docx/pdf/paste paths; full text survives each.
- [ ] 4. Add the text-conservation property test (fast-check) over generated
  section mixes.
- [ ] 5. Re-baseline goldens whose fixtures carry pre-heading content; record
  in the change log that prior hashes attested truncated scans.
- [ ] 6. Full gate green.
