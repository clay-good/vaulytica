# Tasks

- [~] 1. Read each seed authority at its official source and record text, URL, retrieved date, and version history: leginfo.legislature.ca.gov (Civ. Code § 1542, current; pre-2019 text from the chaptered SB 1431), eCFR (16 C.F.R. §§ 433.2, 429.1), statutes.capitol.texas.gov (§ 541.102), uscode.house.gov (18 U.S.C. § 1833(b)(3)). No text enters the table from a secondary source.
- [ ] 2. DKB: `mandated_texts` schema, fetch script, provenance gate in `dkb:build`, validation test; migrate the two Texas literals out of `regime-data.ts`.
- [x] 3. Matching: sliding-window token similarity with an exact whitespace-normalized fast path; threshold chosen by measuring the corpus (no false hit on the 363 specimens; every seeded paraphrase fixture caught); ReDoS-safe by construction (no regex over document text; token arrays).
- [~] 4. `src/engine/rules/text/` factory: `TEXT-<row>` altered / superseded shapes with the word-diff redline (reuse `clause-diff` segments); `TEXT-FORM-<row>` over run properties; gating by family list or registered assertion.
- [~] 5. DOCX ingest: expose `w:sz`, `w:caps`, `w:b` per run on the tree's formatting (bold already carried); PDF text-item size already available; pasted text reports "not checked". **Size is done for both DOCX and PDF (9.1001.0); `w:caps` is not read, and no row needs capitals.**
- [x] 6. Conspicuousness rule over the existing clause locator for warranty disclaimers and liability caps; info severity; citation to U.C.C. § 1-201(b)(10) and § 2-316(2) with retrieved dates.
- [x] 7. Fixtures: exact, paraphrased, superseded, and form-deficient versions of each seed passage; clean documents for each family confirm no false finding. *(Superseded declined — see 9.1004.0 above.)*
- [x] 8. Overlap decisions: for `COMM-206`, the § 429.1, § 1833(b) and § 1542 presence rules and the two Texas rules, decide retire-or-keep-as-absence, with a fixture proving one finding per defect, never two.
- [x] 9. Guards: `rule-completeness`, citation currency (`citation:check`), vacated-authority registry, shall/will and compound-spelling sweeps over the new rule sources; `rule-scaling`.
- [ ] 10. Land with a scheduled DKB rebuild; regenerate goldens once; CHANGELOG lists every corpus finding the change adds.
- [x] 11. Docs: `reference.md` rule table row; `/known-limits` sentence that form is checked only in DOCX and PDF; `adding-a-rule.md` section "adding a mandated text".
- [x] 12. Full gate green.

## Progress — 9.982.0 (slice A: the FTC Holder Rule notice)

- Task 1, in part. 16 C.F.R. § 433.2 was read at eCFR through its official versioner API on 2026-10-20 (both notices, (a) and (b), and the form "in at least ten point, bold face, type"; version 40 FR 53506, Nov. 18, 1975). **Cal. Civ. Code § 1542 is blocked on access:** leginfo.legislature.ca.gov answers 403 to automated reads (both the fetch tool and a plain request), and the spec forbids a secondary source, so its current and pre-2019 rows wait for a person to read them there. §§ 429.1, 541.102 and 1833(b)(3) were not attempted in this slice.
- Task 2, built differently: the table is `src/engine/rules/text/mandated-texts.ts`, a typed source module beside its rules (as the Texas notices are in `regime-data.ts`), not a DKB table, so it lands without a DKB rebuild. The provenance gate is a test: every row names a source on an official host, an ISO date read and a version. Moving it into the DKB, and the Texas literals with it, waits for the scheduled rebuild.
- Task 3: token windows over each paragraph, no regular expression over document text beyond one linear tokenizer. Exact is case- and spacing-blind; near is a window holding at least 85% of the passage's words; a leading "NOTICE" is the passage's heading and not required in the paragraph. The window's edges are refined so the redline names only the changed words. Measured: no TEXT finding on any of the 363 specimens; every altered fixture caught.
- Task 4, in part: `TEXT-001` (present but altered, with the words dropped and added, naming the closest variant) and `TEXT-002` (not in bold face, read only where the file carries run formatting; point size not read). The superseded shape needs § 1542. The rules are ungated: each fires only on a document that carries the passage, which is the evidence it applies; no specimen does.
- Open: § 1542 (access), §§ 429.1, 541.102, 1833(b)(3); tasks 5–6 (point size, conspicuousness); 8 (overlap decisions, none needed yet: no existing rule checks the Holder notice); 10 (DKB rebuild).

## Progress — 9.983.0

16 C.F.R. § 429.1(a), read at eCFR on 2026-10-20. Its statement is required "in substantially the following form", and the rule tells the seller to alter its last sentence when the forms are not attached, so a reworded statement is not a defect. The table gained `wording: "exact" | "substantially"`; `TEXT-001` reads only exact rows, and `TEXT-002` holds the statement to its bold face ("a minimum size of 10 points"; size not read). The first sentence, which states the right, locates it. The residential-solar rules that check the statement's presence are unchanged: they ask whether it is there, this asks how it is set. § 429.1(b)'s notice form and 18 U.S.C. § 1833(b)(3) (content elements, not words, and already checked as presence) are not in the table.

## Progress — 9.984.0

Task 5, the DOCX half: a paragraph carries `min_size_pt`, the smallest point size its text is set in, resolved as Word does (the run's own `w:sz`, its character style, its paragraph style through `basedOn`, the default paragraph style, the document defaults; `docx-sizes.ts`), and absent whenever a link is missing, so a size is reported only when the file states it. `TEXT-002` now reports a notice below the authority's minimum ("set in 8-point type"), and says when the size could not be read. `w:caps` and the PDF text item's size are not read yet; no row needs capitals.

## Progress — 9.985.0

Task 6, narrowed: `TEXT-003` (info) notes a disclaimer of the warranty of merchantability that a Word file sets in regular, mixed-case body type, with no bold run, no capitals, and no heading naming it. § 1-201(b)(10) counts a heading in contrasting type as conspicuous, so a disclaimer under "Disclaimer of Warranties" is not flagged. Liability caps are NOT read, against the proposal: they fall under § 2-719, which sets no conspicuousness requirement, so a note citing § 2-316(2) for a cap would assert law that is not there. The finding never says the disclaimer fails. `COMM-206` is unchanged: it asks whether the clauses are there, from text; this asks how a Word file sets one. Task 8: no overlap to resolve, since no existing rule reads run formatting.

## Progress — 9.986.0

Task 9: the new sources run under the shall/will, compound-spelling, `rule-scaling` and ReDoS guards with the full suite (all green); `citation:check` passes (241 URLs well-formed); no authority cited is in the vacated-authority registry. Task 11: `reference.md` carries the rule row; `/known-limits` says how text is set is read only from a Word file; `adding-a-rule.md` gains "Adding a mandated text" (official source only, `wording`, variants, `form`, fixtures). Still open: § 1542 (leginfo blocks automated reads), § 541.102 (migrating the Texas literals belongs with the DKB move), the DKB table itself (task 10, with the scheduled rebuild), and task 12 once those land.

## Progress — 9.1001.0

Task 5's PDF half, and a defect behind it. `TEXT-002` returned early on any
file with no run formatting, so **the point-size half of the check never ran on
a PDF** — the format consumer paper arrives in. The size was never unavailable:
`src/ingest/pdf.ts` had been reading each text item's rendered size all along
to find headings (`transform[0]`, the size after the page transform, and a PDF
user unit is one point), and simply never put it on the paragraph.

🥇 **And `normalize()` was silently dropping it.** It rebuilds each paragraph as
`{ id, runs }`, so a `min_size_pt` set during ingest did not survive — which is
precisely why the DOCX path calls `attachSizes` AFTER normalizing instead of
setting it inline. That workaround made the field look like it worked while the
hole stayed open for the next producer, which is what a workaround in place of
a fix always does. The normalizer now carries the field.

The two halves of "form" come from different places and a file may answer for
one and not the other: size from a Word file's sizes and styles or from a PDF's
text layer, bold face and capitals from a Word file alone. So the rule no longer
asks "does this file carry formatting?" but "which half can this file answer
for?" — it checks what it can, NAMES the half it could not (never implying it
passed), and advises only on what it read. Telling a PDF's reader to set the
notice bold would assert a defect that file cannot show.

Guards (`tests/integration/mandated-text-pdf-form.test.ts`), each confirmed to
fail with its half of the fix removed — reverting the normalizer's carry, and
restoring the rule's early return, each break it: the ingest records the
smallest rendered size of a paragraph's text; an 8-point notice in a PDF is
reported with "Whether it is bold is not recorded in this file"; a 10-point one
is not (the boundary is `>= 10`); pasted text still says nothing, answering for
neither half. The fixture builds a real PDF parsed by real pdfjs, with the
notice WRAPPED across lines as a generator emits it — a single 300-character
`Tj` came back truncated at 113 characters, which was not run down and is not
claimed either way here, since no real generator writes a line that overruns
the page.

Zero findings moved on the 363 specimens: 369 of 370 regenerated goldens differ
only in the version stamps and `TEXT-002`'s own 1.1.0 → 1.2.0.

Honesty follow-through: `/known-limits` had said how text is set "is read only
from a Word file. A PDF text layer and plain text carry none of it" — true of
bold, false of size, and false specifically because the ingest was already
reading sizes. It and `reference.md`'s rule row now say which part each format
states.

Still open on this change: § 1542 (leginfo blocks automated reads), §§ 429.1(b),
541.102 and 1833(b)(3), the DKB table and the Texas literals' migration (task
2, with the scheduled rebuild), `w:caps` (no row needs it), task 7's fixtures,
and task 12.

## Progress — 9.1004.0 (both "blocked" hosts read; two items DECLINED with reasons)

**Both recorded blocks were wrong, and in the same way.** The spec recorded
Cal. Civ. Code § 1542 as blocked (leginfo answers 403 to a fetch) and
Tex. Bus. & Com. Code § 541.102 as unreachable ("serves its text only to a
browser script"). Both are true of a plain fetch and false of the browser
pane, which rendered each page on 2026-11-23. **A blocked source is blocked at
a HOST, not at a statute** — the same lesson N.Y. Gen. Oblig. Law § 5-702 taught
in 9.1003.0, where the API host 401s and the public page serves the section.
Re-try the other hosts before recording a block.

Reading them settled three open items, two of them as DECLINED rather than
built. That is the point of reading the authority first.

### § 1542 is not a mandated text, and its "superseded" version is not superseded

Task 1 asked for the current and pre-2019 § 1542 text; task 4 asked for a
`TEXT-<row>` **superseded** shape, with the pre-2019 § 1542 as its seed row.
Both are declined:

1. **§ 1542 prescribes no wording for a document.** It is a default rule —
   "A general release does not extend to claims that the creditor or releasing
   party does not know or suspect to exist…" — which parties WAIVE by express
   reference. There is no passage the statute requires an agreement to carry,
   so there is nothing for `TEXT-001` (altered) or `TEXT-002` (form) to be
   altered or misformatted against. `SET-003` already checks for the waiver as
   a presence rule, which is the right shape for it.
2. **The 2018 amendment is declaratory of existing law.** SEC. 3 of the
   chaptered act (Stats. 2018, Ch. 157, SB 1431, read at leginfo on
   2026-11-23) says in terms: "The amendments to Sections 1541 and 1542 of the
   Civil Code made by this act are declaratory of existing law." The change
   added "or releasing party" and "or released party" and the Legislative
   Counsel's Digest calls it a clarification. So a release reciting the
   pre-2019 wording is **not** quoting a superseded rule; the legislature said
   the law did not change. A finding telling an attorney their § 1542 waiver is
   out of date would be wrong.

**The superseded shape therefore has no legitimate seed row and is not built.**
No other row in the table has a version history where the change is
substantive, and a detector with no row that can reach it is dead code — the
failure class `dead-optional-field-sweep` and `2026-10-11-goal-loop-s44` are
about. If a row with a substantive version change is ever added, build the
shape then, with that row as its proof.

### § 541.102 was already exact, and has gained the provenance it lacked

The two TDPSA notices were re-read at statutes.capitol.texas.gov on 2026-11-23
and are **unchanged**: § 541.102(b) "NOTICE: We may sell your sensitive
personal data." and (c) "NOTICE: We may sell your biometric personal data."
(Acts 2023, 88th Leg., R.S., Ch. 995 (H.B. 4), Sec. 2, eff. July 1, 2024).

Task 2's migration of these literals into `mandated_texts` is **declined as
specified**: the privacy pack already matches them whitespace-normalized and
case-sensitively and reports an altered rendering, so adding them to
`MANDATED_TEXTS` would have `TEXT-001` report the same defect a second time —
the thing task 8 exists to prevent ("one finding per defect, never two").

What the migration was really worth is the provenance, and that is built:
`TX_SALE_NOTICES` in `src/privacy/regime-data.ts` now carries each notice's
text, citation, official source, read date and enacting act, with a guard
(`regime-data.test.ts`) holding it to the same standard `MANDATED_TEXTS` is
held to. Before this they were bare string constants with the URL in a
comment and no date — an exact-wording passage was the loosest-held authority
in the tree, which is backwards, since its whole point is that the words are
the requirement.

### What is left on this change

- Task 2's DKB `mandated_texts` table and its `dkb:build` provenance gate (the
  table still lives beside its rules).
- Task 7's fixtures for the two FTC passages, and the clean documents per
  family.
- Task 1's 18 U.S.C. § 1833(b)(3): **re-examined and declined as a mandated
  text.** § 1833(b)(3)(A) requires an employer to "provide notice of the
  immunity set forth in this subsection" and expressly permits a
  cross-reference to a policy document instead; it prescribes no wording. It is
  a required DISCLOSURE, not a fixed passage, and the existing DTSA presence
  rule is the right shape.

## Progress — 9.1005.0 (task 7, and the defect the standing sweep found)

Task 7 closed. The exact, paraphrased and form-deficient fixtures were already
in `text.test.ts` and `mandated-text-pdf-form.test.ts`; the superseded shape is
declined (9.1004.0). What was missing was the **clean-document half**, and task
3 had recorded it as a one-time measurement — "no false hit on the 363
specimens" — written into this task list with nothing holding it. A number in a
task list is not a guard; the same gap for `READ-003` failed three times the
moment it was made standing.

`tests/integration/mandated-text-corpus.test.ts` is the standing version: the
sweep over every specimen, a clean retail instalment contract carrying
§ 433.2(a)'s notice verbatim, and a REACH case so zero hits cannot be mistaken
for a dead rule.

🥇 **The reach case failed, and it was a real gap.** `NEAR = 0.85` requires a
window to carry 85% of the passage's words. A notice with its LAST SENTENCE
dropped keeps ~75%, so the document was not recognized as carrying the notice
at all and nothing was reported. The dropped sentence is the recovery cap
("RECOVERY HEREUNDER BY THE DEBTOR SHALL NOT EXCEED AMOUNTS PAID BY THE DEBTOR
HEREUNDER") — the half a drafter has a reason to omit, and a presence pattern
keyed on the opening passes it too.

Lowering `NEAR` was the wrong fix: the threshold was corpus-measured, and a
looser multiset share starts calling ordinary paragraphs notices. The fix is a
second instrument — **twelve consecutive words of the passage's opening,
verbatim and in order, identify it** whatever share of the tail survives, and
the word diff then says what is missing. The anchor path runs only where the
share-based pass found nothing, so no existing verdict moves: all 18 unit cases
and the 5 PDF-form cases are unchanged, and the corpus sweep stays at zero.

⚠️ One trap on the way: an early `toks.length < ceil(n * NEAR)` guard skipped
the variant before the anchor path could run, so the first version of the fix
changed nothing. The guard now bounds the WINDOW loop, not the variant.

Still open, and **not blocked on anyone**: task 2's DKB `mandated_texts` table
with its fetch script and `dkb:build` provenance gate, and task 10's scheduled
rebuild. Both authority tables added by these changes — `MANDATED_TEXTS` and
`READABILITY_STANDARDS` — still live beside their rules, which means they are
the only authorities in the product not held to a build-time provenance gate.
That is the next chunk.
