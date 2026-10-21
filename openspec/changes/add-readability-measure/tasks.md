# Tasks

- [ ] 1. Syllable counter: rules plus a committed exception list; measure against a 5,000-word reference list and commit the accuracy figure; version constant.
- [ ] 2. `src/report/readability.ts`: tokenization under the model act's rules over the tree (headings and captions excluded, signature block and TOC excluded), score, longest sentence, exclusions list; render-side block in JSON, DOCX appendix, HTML.
- [ ] 3. DKB `readability_standards`: read each state's statute at its official source (start with NY, FL, MI, ME, CO, TX, CA, WV, and the model-act states), record threshold, scope, TOC and type-size requirements; provenance gate.
- [ ] 4. `READ-001`, `READ-002`, `READ-003` assertion-gated; register `readability-<state>` and `readability-ny-consumer`; CLI `--readability`; browser selector.
- [ ] 5. Fixtures: a policy under and over threshold, a long policy without a TOC, an uncaptioned lease; property test that the block never changes `result_hash`.
- [ ] 6. Docs: `reference.md` section, `/known-limits` sentence on sampling and exclusions not applied, `deadlines.md`-style note `readability.md` with the formula and the statute table.
- [ ] 7. Full gate green.

## Progress — 9.987.0 (slice A)

- Task 1, measured on a smaller list than the task names: `src/extract/syllables.ts` (rules plus a short exception list, `SYLLABLE_COUNTER_VERSION`) against `syllables-reference.ts`, 348 words: the specimen corpus's most frequent words and common short words, each counted from dictionary syllabification, leaving out words dictionaries disagree on (interest, every, hours, entire, required). 345 of 348 correct; the test holds at least 98%. The rules were corrected after reading the list's misses (plural "-ies", "y" between vowels, a silent "e" before "-ment", syllabic "-ges"/"-ces", here/there compounds, "any"), so this is not a held-out figure. The 5,000-word reference the task names needs a licensed pronunciation dictionary (CMUdict), which this build did not download.
- Task 2, the JSON half: `src/report/readability.ts` computes the score as Fla. Stat. § 627.4145(5) prints the method (read at leg.state.fl.us on 2026-10-20): contractions, hyphenated words and spaced numerals and letters one word each; a sentence ends at a period, semicolon or colon, not at "Inc." or a clause number; headings, captions, signature lines and table-of-contents lines left out. The block names its method, the longest sentence and where it is, what it left out, and what a statute allows that it does not apply (sampling; defined words, medical terminology, language required by law). Every JSON report carries it, outside `run`. Over the 363 specimens: median 43.1, from 18.1 (a board resolution) to 101.3; about 0.45 ms a document. The DOCX appendix and the HTML section are not built yet.
- Task 3, in part: Florida's § 627.4145 was read at its official source (threshold 45; a table of contents or index above 3,000 words or three pages; section titles in bold or otherwise standing out). New York's nysenate.gov answers automated reads with a bot challenge, and was not read.

## Progress — 9.988.0

Task 4, in part: `READ-001` (score below the asserted statute's minimum) and `READ-002` (a form over the statute's word limit with no table of contents or index) under the registered `readability` assertion, from `--readability fl` on the CLI and `readability` in `vaulytica.config.json`, with the asserted standard stamped into the run (`asserted_readability`, inside the hash only when asserted) and re-derived by `verify`. The tab's pipeline takes the same option to the same hash (cross-surface test); its selector is not built, nor the bundle path, the MCP server or the Action input. `READ-003` (NY GOL § 5-702) waits for New York's text. Task 3: the standards table is a provenance-guarded source module with the Florida row, not yet a DKB table. Task 6: `docs/readability.md` and the `reference.md` flag row.

## Progress — 9.989.0

Task 2's report half: the HTML and Word covers carry a "Reading ease" line (score, words and sentences, "informative only", or the asserted statute and its minimum). A full appendix with the longest sentence and the exclusions is the JSON block's; the covers give the line.

## Progress — 9.990.0

Task 4's browser selector: "Reviewing an insurance policy form? Hold it to a readability statute…" beside the estate panel (`readability-panel.ts`, its choices pinned to `READABILITY_STANDARDS` by test). The chosen statute reaches the single-document run and its frame re-runs; an e2e chooses Florida, pastes a dense policy and finds the reading-ease item on the page. The eager entry is 29.44 KB of its 30 KB. Not built: the bundle path, the MCP server and the Action input.
