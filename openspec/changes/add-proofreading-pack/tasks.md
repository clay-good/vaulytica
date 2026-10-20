# Tasks

- [x] 1. Measure first: prototype each detector as a script over the 363 specimens and the clean documents; read every hit; commit the counts and the false-hit reasons before writing rules.
- [x] 2. `PROOF-001` balance scanner (enumerator strip, curly-quote pairing, apostrophe exclusion); `PROOF-002` weekday arithmetic reusing `deriveDate`'s calendar; `PROOF-003` repeat detector with allow-list.
- [x] 3. `PROOF-004` over the party extractor's registered names with the CROSS-PARTY-001 short-form rule; `PROOF-005` over outline + crossrefs; `PROOF-006` enumerator sequencer with the `(i)` disambiguation; `PROOF-007` phrase table and majority-form comparison.
- [x] 4. Register the `PROOF` namespace (always-on); add to `LAUNCH_RULES`; launch-set count in `reference.md` and the site.
- [x] 5. Fixtures and negative tests per rule; the clean-document sweep; corpus firing counts by equality; format-invariance and shall/will relations re-run.
- [x] 6. Static guards: `rule-scaling` (no quadratic patterns), compound-spelling, section-abbreviation, apostrophe-tolerance over the new sources.
- [x] 7. Regenerate goldens once; CHANGELOG lists each specimen that gained a finding and why it is true.
- [x] 8. Full gate green.

## Progress

- 9.960.0 shipped slice A: PROOF-001/002/003. Measured over the specimens first. The only false hits were caption ")" columns, bare enumerators, multi-paragraph quotations, and repeats of a capitalized word that ingest produced by joining lines with a space. The corpus count is pinned at 0 in `tests/integration/proofreading-corpus.test.ts`. PROOF-002 does its own UTC arithmetic, not `deriveDate`. It covers "Weekday, Month D, YYYY" and "Weekday D Month YYYY". A date with no year is not yet reported (still in task 2's scope).
- 9.961.0 shipped PROOF-005 (titled cross-reference against the cited heading, run-in or not) and PROOF-006 (enumerator gaps read in document order, so paragraph breaks cannot move it). The corpus pin now covers five rules and both clean deal rooms.
- 9.963.0 shipped PROOF-007. The document's majority form is the reference; only spelling-level variants are compared.
- 9.964.0 shipped PROOF-004. It reads the document's text for two spellings of ONE corporate form; different forms can be parent and subsidiary. All seven rules are shipped.
- Task 6: `recognizerSources` walks `src/engine/rules` recursively from disk, so the static guards read all seven rule files (32 regexes), and every one passed. Task 7: each release's goldens moved only in the execution log; no specimen gained a finding, so none needed a "why it is true" line.
- **Declined, measured: PROOF-002's info half (a date with no year).** Over the specimens it draws 24 hits in 19 documents, and none is an error.
  - Recurring annual dates: "the fiscal year ends on December 31", "a Schedule K-1 by March 15", "after September 30".
  - A list that states its year once: "May 30, June 27, and July 29, 2025".
  - The recurring ones carry no textual marker to exclude them by. Any version either fires on clean documents, which this spec's own rule forbids, or is too narrow to fire at all.
  - Reopen it if a corpus document ever carries a real missing-year error.
