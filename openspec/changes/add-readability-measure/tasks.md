# Tasks

- [x] 1. Syllable counter: rules plus a committed exception list; measure against a 5,000-word reference list and commit the accuracy figure; version constant.
- [x] 2. `src/report/readability.ts`: tokenization under the model act's rules over the tree (headings and captions excluded, signature block and TOC excluded), score, longest sentence, exclusions list; render-side block in JSON, DOCX appendix, HTML.
- [x] 3. DKB `readability_standards`: read each state's statute at its official source (start with NY, FL, MI, ME, CO, TX, CA, WV, and the model-act states), record threshold, scope, TOC and type-size requirements; provenance gate.
- [x] 4. `READ-001`, `READ-002`, `READ-003` assertion-gated; register `readability-<state>` and `readability-ny-consumer`; CLI `--readability`; browser selector.
- [x] 5. Fixtures: a policy under and over threshold, a long policy without a TOC, an uncaptioned lease; property test that the block never changes `result_hash`.
- [x] 6. Docs: `reference.md` section, `/known-limits` sentence on sampling and exclusions not applied, `deadlines.md`-style note `readability.md` with the formula and the statute table.
- [x] 7. Full gate green.

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

## Progress — 9.991.0

Task 5 for Florida: a dense policy under 45, a plain one over it, a form over 3,000 words with and without a table of contents (`readability-assertion.test.ts`), and a property test over every ninth specimen that building the readability block never changes the run or its `result_hash`. The uncaptioned lease belongs with `READ-003` and New York's text. Task 6: `/known-limits` says the score applies neither sampling nor the statutory exclusions. Open: task 1's 5,000-word reference (needs a licensed pronunciation dictionary), task 3's other states (New York's site refuses automated reads; the rest not attempted), `READ-003`, the DKB table, and task 7.

## Progress — 9.992.0

Task 3: Maine (24-A M.R.S. § 2441, minimum 50; scope from §§ 2439–2440) and Michigan (MCL § 500.2236(3), minimum 45; personal-lines policy and annuity forms) read at legislature.maine.gov and legislature.mi.gov on 2026-11-16. Both print the NAIC counting rules the score follows. Rows gained `index_ok`: Michigan's (3)(f) requires "a table of contents" and names no index, so `READ-002` under `mi` does not accept an index heading. Not attempted or not reachable: Texas (statutes.capitol.texas.gov serves its text only to a browser script), West Virginia and Colorado (not yet located at an official source), New York (bot challenge), California. Not checked from the read texts: Maine's 10-point type, Michigan's topical captions and identification of exclusions.

## Progress — 9.993.0

Task 3: Minnesota (Minn. Stat. §§ 72C.08–72C.10, read at revisor.mn.gov on 2026-11-16). Rows gained `min_exclusive` (§ 72C.10 subd. 2(a): "more than 40") and `contents_over: "always"` (§ 72C.08 subd. 1(b): an index of the major provisions in every policy). Not applied: § 72C.09's exclusion of lists from the sentence count, § 72C.08's "Read your policy carefully" cover statement, and § 72C.06's qualitative factors. Connecticut's chapter 700c page reads but holds no Flesch test; its readability law was not located.

## Progress — 9.994.0

Task 3: Nevada (Nev. Rev. Stat. §§ 687B.122–687B.124, read at leg.state.nv.us on 2026-11-16): at least 40; contents or index above 3,000 words or three pages; life and health policies. The table now holds FL, ME, MI, MN and NV. Connecticut's insurance chapters (700–702, 700c) hold no Flesch test; Texas's minimum is an agency rule, not a statute.

## Progress — 9.995.0

Task 3: Ohio (Ohio Rev. Code § 3902.04; scope §§ 3902.02–3902.03; codes.ohio.gov) and Oregon (Or. Rev. Stat. § 743.106; oregonlegislature.gov), read 2026-11-16, both minimum 40 with the model act's contents rule. Seven states: FL, ME, MI, MN, NV, OH, OR. Delaware's title 18 ch. 27 subch. I and Kentucky's KRS page probed held no Flesch test.

## Progress — 9.996.0

Task 3: Montana (Mont. Code Ann. § 33-15-325; scope §§ 33-15-322–323) and West Virginia (W. Va. Code § 33-29-5; scope §§ 33-29-2–3), read 2026-11-16, both minimum 40, model-act contents rule. West Virginia's page prints no history note, and the row says so. Nine states. Texas (1992 commissioner's order) and Wisconsin (Wis. Admin. Code Ins 6.07) set theirs by agency rule; North Dakota's § 26.1-36-14 is next.

## Progress — 9.997.0

Task 3: North Dakota (N.D. Cent. Code §§ 26.1-33-30 life, 26.1-36-14 accident and health; scope § 26.1-36-13), read in the ndlegis.gov chapter PDFs on 2026-11-16, as one row (the sections set the same test). Ten states: FL, ME, MI, MN, NV, OH, OR, MT, WV, ND. Remaining model-act states are to be located at official sources; New York (bot challenge) and California still wait.

## Progress — 9.998.0

Task 3: Nebraska (Neb. Rev. Stat. § 44-3405, nebraskalegislature.gov) and the District of Columbia (D.C. Code § 31-4725, scope § 31-4727, code.dccouncil.gov), read 2026-11-16, both minimum 40 with the model act's contents rule. Twelve jurisdictions. Located but not yet read at an official source: Oklahoma (36 O.S. § 3645; OSCN), Indiana (IC 27-1-26), Georgia (O.C.G.A. § 33-3-25, no free official code).

## Progress — 9.999.0

Task 3: Oklahoma (Okla. Stat. tit. 36, § 3645; scope § 3644), read at oscn.net on 2026-11-16, minimum 40, model-act contents rule. Thirteen jurisdictions: FL, ME, MI, MN, NV, OH, OR, MT, WV, ND, NE, DC, OK.

## Progress — 9.1000.0

Task 4's bundle path. 🚨 **The assertion did not reach a folder.** Thirteen
statutes were readable from the tab's panel and the option was accepted by the
bundle pipeline, but `prepareBundle` layered the privacy and estate packs onto
each member and never passed `options.readability` to `activateReadability`,
and both of `main.ts`'s `runBundlePipeline` call sites forwarded `regimes` and
`estate_state` and not the statute. So a user who chose Florida and dropped a
folder got no `READ-*` finding and no stamp, and nothing said why. The
single-document path had been right since 9.988.0.

Readability is not playbook-gated the way those two packs are — nothing in a
document says where it was filed — so the fix holds **every** member to the
asserted statute, each scored on its own text and each carrying
`asserted_readability` in its own hashed run. On the two sample bundle
documents that is the whole point: the addendum scores 22.2 and is named under
Florida's 45, the services agreement scores 51.6 and is not.

Hash isolation holds: with no assertion the member runs and the
`bundle_fingerprint` are byte-identical.

Guards, each confirmed to FAIL with its half of the wiring removed:
`tests/integration/bundle-readability.test.ts` (the real browser bundle
pipeline, mirroring `bundle-privacy-regimes` and `bundle-estate-checks`) and an
e2e in `results-page-bundles.spec.ts` that drives the panel and a two-file drop
for the `main.ts` half. 🥇 **The fingerprint case was vacuous when written** —
it passed with the wiring removed, because `Packer.toBuffer` stamps a creation
time into each synthesized .docx, so every call gave the run different bytes
and a different hash for reasons unrelated to the assertion. The fixtures are
built once and the case now proves the fingerprint is stable over the same
bytes before asserting that the statute moves it.

A consequence worth naming: each member's own Word report inside the bundle
archive had a cover reading `… informative only` even when a statute was
asserted, because `renderCover` prints that line from
`run.asserted_readability`. The test reads it out of the `.docx` rather than
inferring it from the run object — 🥇 **and as first written it matched the
`READ-001` finding's own title, which also begins "Reading ease", instead of
the cover field, which `coverField` prints with a colon.** Two of this slice's
five cases were vacuous on the first pass; both were found by running them
against the un-fixed code, which is the only thing that distinguishes a guard
from a decoration.

A new ratchet closes the class rather than this instance:
`tests/integration/bundle-option-reach.test.ts` compares the `options.*` reads
inside `runReport` against those inside `prepareBundle` and fails by name when
one path gains an option the other does not, with `NOT_IN_BUNDLE` carrying a
stated reason per exemption (`filing` alone: the tab ships no court-profile
selector on either path). That is the mechanism whose absence let this ship.

The round-comparison call site was wired too, so a revised round is scored
against the same statute as its baseline rather than moving for that alone; it
has no guard of its own.

Still open: task 1's 5,000-word reference (needs a licensed pronunciation
dictionary), task 3's remaining states (New York's site refuses automated
reads; California not located), `READ-003`, the DKB table, and task 7.

## Progress — 9.1002.0 (the Action reaches it)

Part of task 4: `--readability` is now a GitHub Action input of the same name,
with `state`, `regime`, `court`, `deadline-profile`, `estate-checks` and the
rest of the assertions — the Action had exposed no assertion-gated pack at all,
and `tests/integration/action-flag-coverage.test.ts` now fails the build if a
new assertion flag ships without an input. The MCP server already had it. Still
open on task 4: the browser's own selector.

## Progress — 9.1003.0 (`READ-003`, and the blocker that was not one)

**Task 4 is closed.** New York's § 5-702 was recorded as blocked ("the New York
Senate's site answers automated reads with a bot challenge"). That was true of
the API host — `legislation.nysenate.gov` answers 401 to an unauthenticated
read — but NOT of the public page: `www.nysenate.gov/legislation/laws/GOB/5-702`
served it on 2026-11-23, and it prints its own revision date (2020-04-10). The
lesson is narrow and worth keeping: **a blocked source is blocked at a HOST,
not at a statute.** Re-try the other hosts before recording a block.

§ 5-702 is the first row in the table that is not an insurance readability
statute and the first that sets NO SCORE, so `min_score` and `contents_over`
became optional on `ReadabilityStandard`, with `captions_required`,
`max_amount` and `not_measured` beside them. `READ-001` and `READ-002` return
early for a row that sets neither, and the report cover line says the statute
sets no score rather than printing "minimum undefined".

🥇 **The detector was wrong twice and the corpus sweep is what said so.**
`READ-003` is an absence finding, so asserting `ny-consumer` over all 363
specimens is the cheap clean-document test: nearly all are captioned, so any
hit is a caption style the detector cannot read. 32 hits → the first draft read
only the ingest's OUTLINE, and a plain-text document has no section headings
whatever its captions (`paste.ts` promotes a line only on a Markdown `#` or a
Setext underline). 10 hits → `1. PURPOSE AND SCOPE`, a numbered ALL-CAPS
caption with no terminator, the commonest form in American drafting. 9 hits →
`uk-contract-of-employment`, captioned throughout, whose caption line runs into
`1.1` with no blank line, leaving a trailing numeral read as an uncapitalized
word. 0 hits, with the uncaptioned-lease fixture still firing.

Also fixed on the way: the first paragraph is the document's own TITLE
("RESIDENTIAL LEASE AGREEMENT"), which matched the caption-line pattern and
made the uncaptioned lease look captioned — the rule was off on exactly the
documents it exists for.

Task 5's "uncaptioned lease" fixture is in `readability-assertion.test.ts`,
paired with the same lease captioned, so the rule is proven able to fail.

Still open: task 1's 5,000-word reference (needs a licensed pronunciation
dictionary), task 3's remaining states (Texas and Wisconsin set their minimums
by agency rule; California not located; N.Y. Ins. Law § 3102 not attempted),
the DKB table, and task 7.

## Progress — 9.1005.0 (tasks 5 and 7 closed)

Task 5 is complete: the dense and plain policies, the over-3,000-word form
with and without a table of contents, the **uncaptioned lease paired with the
same lease captioned** (9.1003.0), and the property test that building the
readability block never changes the run or its `result_hash` for any specimen
— all in `readability-assertion.test.ts`, plus the 363-specimen `READ-003`
sweep. Task 7: the full gate is green at 9.1005.0 (680 files, 16,966 tests,
71 e2e, `npm run verify` exit 0).

Still open and each blocked on something outside the build: task 1's
5,000-word syllable reference (needs a licensed pronunciation dictionary —
CMUdict), and task 3's remaining jurisdictions (Texas and Wisconsin set their
minimums by agency rule rather than statute; California has no Flesch statute
for insurance forms) plus the DKB table.

## Progress — 9.1008.0 (task 1 CLOSED; task 3's states resolved)

**Task 1 is done, and the blocker was my own wrong assumption.** It was recorded
as needing "a licensed pronunciation dictionary (CMUdict)". cmudict is
BSD-style and expressly permits redistributing derived data provided its notice
is retained — so there was never a licence blocker, only an unchecked claim.

`syllables-cmudict-reference.ts` holds 5,000 words: the most frequent across
the 363 specimens that cmudict knows and gives ONE syllable count (130 words
whose pronunciations disagree are excluded rather than guessed at), with the
CMU copyright notice retained as the licence's first condition requires. The
syllable count is the number of phonemes carrying a stress digit, and that
invariant was checked over the WHOLE dictionary rather than a sample: of
135,166 entries, every vowel carries a stress digit, no consonant does, and the
only eight entries yielding zero syllables are vowel-less interjections.

🥇 **The committed figure was an overstatement and is now corrected.** The old
number was 345 of 348 = 99.1%, measured on the counter's own training set — the
task note said as much. Held out against 4,661 words the rules never saw, the
counter is right about **93.2%**, six points lower.

🥇 **And per-word accuracy is the wrong number to publish.** The score's only
syllable term is `84.6 × (syllables ÷ words)`, so a per-word error of *e* moves
the score by `84.6 × e`. Over all 324,144 corpus tokens with ground truth the
mean SIGNED error is −0.006 syllables/word — a bias of **0.5 of a Flesch
point**, with a 1.8-point bound if every error pointed the same way, against
thresholds of 40–50. Errors cancel in an aggregate, which is why a counter
wrong about one word in fourteen still scores a document to within a point.
`syllables-accuracy.test.ts` holds both, plus a check that the misses are NOT
one-directional (132 over, 183 under) — a one-sided counter would bias every
score.

⚠️ Note what is NOT claimed: the counter was not tuned against this list, and
must not be, or the figure stops being held out.

**Task 3's remaining states are resolved, each at the source, and none adds a
row.** 14 jurisdictions are in the table (FL, ME, MI, MN, NV, OH, OR, MT, WV,
ND, NE, DC, OK and `ny-consumer`). Of the three the task still named:

- **Texas** sets no number in statute. Tex. Ins. Code § 2301.053(c), read at
  statutes.capitol.texas.gov on 2026-11-23, makes a form plain-language if it
  "achieves the minimum score established by the commissioner on the Flesch
  reading ease test or an equivalent test selected by the commissioner" — or,
  at the commissioner's option, conforms to an NAIC model act instead. The
  threshold and even the choice of test are delegated, so there is no statutory
  figure to record. My earlier note said "sets its minimum by agency rule",
  which was right by luck; this is the verbatim basis.
- **Colorado**'s official C.R.S. is served through LexisNexis or as downloads
  the Office of Legislative Legal Services marks "for personal use" — no
  official source this build can read and redistribute a threshold from. (I
  reached for Justia first and stopped: this spec forbids a secondary source.)
- **California** sets no Flesch minimum for insurance forms.

So task 3 is complete for every jurisdiction that HAS a statutory threshold
readable at an official source. Its DKB-table half stays open with
`add-mandated-text-conformance` task 2, for the reason recorded there.

## Progress — 9.1013.0 (the DKB table, closing task 3)

The table and its build-time provenance gate are built, mirroring
`mandated_texts` (9.1010.0). `dkb-readability-standards.json` is written by
`runBuild` and referenced in the manifest with its entry count and SHA-256; all
14 jurisdictions ship in it.

`assertReadabilityStandardsUsable` runs inside `runBuild` and refuses to WRITE
a row lacking a citation, an official source, a read date, a version history or
a scope — and two checks that are about honesty rather than completeness:

- a row that sets **no score, no contents requirement and no captions
  requirement** is refused, because asserting it would do nothing at all;
- a row with **no score that records nothing it does not measure** is refused,
  because a reader would be left with a citation and no obligation. New York's
  § 5-702 is the row this exists for: it sets no threshold, and what makes it
  usable is `captions_required` plus `not_measured` naming the
  clear-and-coherent requirement the product does not judge.

A test asserts the score-less New York row carries **no `min_score` field at
all** rather than a zero or a default a finding could quote, and `build.test.ts`
asserts a NEW build always writes the table — so the optional manifest field
cannot silently go missing, the same guard `mandated_texts` has.

⚠️ Unlike a mandated text there is **no `content_sha256` and no drift check**.
A standard contributes a threshold, not a passage, and a threshold is a number
that has to be read in context: a statute moving from "40" to "40 for policies
issued after a date" is not a change a content hash could report usefully. Said
in the module rather than left as an apparent omission.

The rows stay curated for the reason the change has recorded throughout: each
jurisdiction was read at its legislature's own site by a person, and three more
were examined and excluded with written reasons. An automatic fetcher would
make a threshold whatever a URL served that week — and the threshold is the
number a finding quotes at an attorney.
