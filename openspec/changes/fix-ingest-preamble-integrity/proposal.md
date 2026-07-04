# fix-ingest-preamble-integrity

## Why

DOCX and PDF ingest silently discard every paragraph that appears before the
document's first heading. `src/ingest/docx.ts:170` and `src/ingest/pdf.ts:288`
both end with `if (!promoted && sections.length > 1) sections.shift();` — but
`promoted` is only ever set when the first heading arrives while the root
section is still **empty** (docx.ts:97, pdf.ts:249). So whenever that `shift()`
fires, the root section it deletes always holds real content. The paste path
has the correct guard (`src/ingest/paste.ts:122` drops the root only when
`root.paragraphs.length === 0`); docx/pdf forgot it.

The discarded region is exactly the contract preamble — the title typed as
plain bold text, "THIS AGREEMENT is made between…", the parties, recitals, and
effective date — the region attorneys most need scanned. Verified live through
the shipped CLI: a DOCX whose 30-word preamble contains "unlimited liability
and waives all warranties" before a Heading-1 produces a report with
`word_count: 6` and no trace of the preamble text; every rule ran against a
document missing its parties and recitals and returned a confident, clean-looking
report. This is silent under-scanning — the worst failure mode for a tool whose
promise is "we deterministically checked all of it" — and it affects the
browser and the CLI identically (shared `src/ingest/`).

## What Changes

- docx and pdf ingest adopt the paste-path guard: the root section is dropped
  only when it is genuinely empty. Pre-heading paragraphs stay in the tree,
  are scanned by every rule, and count toward `word_count`.
- A shared ingest-fidelity contract test feeds the same preamble-bearing
  document through all three ingest paths (docx, pdf, paste) and asserts the
  full text survives into the flattened tree — so the three paths can never
  diverge on this again.
- A conservation property test: for generated documents, the character count
  of extracted paragraph text is never reduced by section restructuring.

## Impact

- Affected specs: `ingest-fidelity` (new capability spec)
- Affected code: `src/ingest/docx.ts`, `src/ingest/pdf.ts`, new
  `src/ingest/ingest-fidelity.test.ts`; existing goldens whose fixtures have
  pre-heading content will re-baseline (their old hashes attested a truncated
  scan — the re-baseline is the fix working)
- Risk: `result_hash` changes for any real document with pre-heading content;
  that is intended and unavoidable. Lands with the other hash-affecting fixes
  (after `fix-dkb-build-integrity`/`fix-cli-browser-parity`) so goldens
  re-baseline once.
