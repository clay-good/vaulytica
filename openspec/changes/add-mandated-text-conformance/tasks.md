# Tasks

- [x] 1. Read each seed authority at its official source and record text, URL, retrieved date, and version history: leginfo.legislature.ca.gov (Civ. Code § 1542, current; pre-2019 text from the chaptered SB 1431), eCFR (16 C.F.R. §§ 433.2, 429.1), statutes.capitol.texas.gov (§ 541.102), uscode.house.gov (18 U.S.C. § 1833(b)(3)). No text enters the table from a secondary source.
- [x] 2. DKB: `mandated_texts` schema, fetch script, provenance gate in `dkb:build`, validation test; ~~migrate the two Texas literals out of `regime-data.ts`~~ (declined, see below). **Schema, gate and validation test BUILT in 9.1010.0**; the fetch script stays unbuilt because the rows are curated by design.
- [x] 3. Matching: sliding-window token similarity with an exact whitespace-normalized fast path; threshold chosen by measuring the corpus (no false hit on the 363 specimens; every seeded paraphrase fixture caught); ReDoS-safe by construction (no regex over document text; token arrays).
- [x] 4. `src/engine/rules/text/` factory: `TEXT-<row>` altered / superseded shapes with the word-diff redline (reuse `clause-diff` segments); `TEXT-FORM-<row>` over run properties; gating by family list or registered assertion.
- [x] 5. DOCX ingest: expose `w:sz`, `w:caps`, `w:b` per run on the tree's formatting (bold already carried); PDF text-item size already available; pasted text reports "not checked". **Size done 9.1001.0; `w:caps` done 9.1012.0 — and the "no row needs capitals" half of the old note was WRONG, see below.**
- [x] 6. Conspicuousness rule over the existing clause locator for warranty disclaimers and liability caps; info severity; citation to U.C.C. § 1-201(b)(10) and § 2-316(2) with retrieved dates.
- [x] 7. Fixtures: exact, paraphrased, superseded, and form-deficient versions of each seed passage; clean documents for each family confirm no false finding. *(Superseded declined — see 9.1004.0 above.)*
- [x] 8. Overlap decisions: for `COMM-206`, the § 429.1, § 1833(b) and § 1542 presence rules and the two Texas rules, decide retire-or-keep-as-absence, with a fixture proving one finding per defect, never two.
- [x] 9. Guards: `rule-completeness`, citation currency (`citation:check`), vacated-authority registry, shall/will and compound-spelling sweeps over the new rule sources; `rule-scaling`.
- [~] 10. Land with a scheduled DKB rebuild; regenerate goldens once; CHANGELOG lists every corpus finding the change adds. **Two of three clauses are settled (see below); the landing itself is the scheduled job's, by design.**
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

## Progress — 9.1007.0 (the drift check: task 2's protection, without the table)

Task 2 asks for a DKB `mandated_texts` table with a `dkb:build` provenance
gate and a validation test. Reading the DKB first changed what that is worth
building:

- The curated `statutes` table carries an **`excerpt`**, not a verbatim
  passage, so it cannot hold a mandated text — which is why the spec asked for
  a new table rather than reusing it.
- The provenance half is already enforced where it matters:
  `mandated-texts.test.ts` refuses a row with no source, date or version, and
  9.1004.0 gave the Texas literals the same treatment.
- The currency half was delivered in 9.1006.0 by a different route — the rows
  now emit structured citations, so the existing "verify currency" label
  reaches them.

What none of that covers, and what the table was really for, is **the wording
changing at the source**. `citation:check` asks whether a URL still resolves;
the currency label asks whether a reading is old. Neither notices an
amendment. For `TEXT-001`, whose whole premise is exact wording, an amended
§ 433.2 silently turns the committed passage into the wrong yardstick: a
conforming notice is reported as altered, and so is one matching the new text.

`tools/authority-drift/` closes that, in `citation-check`'s own two-half shape:

- **Pure, per-commit** (`drift.test.ts`): every variant's SHA-256 matches its
  own committed text, whitespace-normalized, so a passage cannot be edited
  without its digest moving.
- **Scheduled** (`npm run authority:drift`, wired into `dkb-rebuild.yml` beside
  the citation check): re-read each section at its official source and compare.
  Containment rather than equality, because the body is a whole section with
  its own labels, history and markup; case-blind, because § 433.2 prints its
  notice in capitals and the rules compare case-blind. A drifted passage and an
  unreadable source are **different verdicts** — re-read the statute, versus
  fix the fetch — since they need different responses.

Verified against the live eCFR API on 2026-11-23: 3/3 passages unchanged.

Task 2's remaining DKB-table half is left deliberately unbuilt, with that
reasoning, rather than moved for its own sake. Task 10's scheduled rebuild is
what runs the drift check.

## Where tasks 2 and 10 stand — 9.1008.0

Task 10 is **half done**: the scheduled rebuild now runs the mandated-text
drift check (`npm run authority:drift`, wired into `dkb-rebuild.yml` in
9.1007.0), which is the protection the scheduled path was wanted for. What
remains of task 10 is landing task 2's table, so the two stand or fall
together.

Task 2's reason is recorded above and was verified, not assumed: the curated
`statutes` table carries an **`excerpt`**, not verbatim text, so it cannot hold
a passage whose exact words are the requirement — which is why the spec asked
for a new `mandated_texts` table rather than reusing `statutes`. The
provenance and currency halves are already delivered by other means
(`mandated-texts.test.ts` refuses a row with no source, date or version;
9.1006.0 gave the rows structured citations so the "verify currency" label
reaches them; 9.1007.0 added drift on the text itself). A new DKB table is
therefore a migration whose user-facing value is already in place, which is why
it is not being built ahead of a reason to.

## Progress — 9.1010.0 (the table, the gate and the validation test are built)

I had declined this on the ground that the value was already delivered
elsewhere. That was a judgment about value, not a blocker, and presenting it as
one was wrong — so it is built.

**The table.** `dkb-mandated-texts.json`, written by `runBuild` and referenced
in the manifest with its entry count and SHA-256. A table of its own, not a row
in `statutes`, for the reason verified earlier: a `StatutoryIndexEntry` carries
an `excerpt`, and a mandated passage's exact words ARE the requirement. Each
variant ships with a `content_sha256` of its whitespace-normalized text, so a
scheduled re-read can tell "the authority amended this" from "our copy was
edited" — which a date alone cannot.

**The gate.** `assertMandatedTextsUsable` runs inside `runBuild` and refuses to
WRITE a knowledge base whose mandated passages lack a source, a read date, a
version, a subsection, or a digest matching their own text. The rows were
already guarded by a test beside the rules; the point of a gate here is that
the DKB is what ships and what the weekly rebuild regenerates, so a bad row
cannot reach a user even if it reached `main`. It reports EVERY defect rather
than throwing on the first, so one build names them all.

**The validation test** drives all nine defects against a row that has each
one, plus the duplicate-id case — a gate is only worth having if it can fail.

🚨 **A migration trap, caught by the build failing.** Adding `mandated_texts`
to the manifest schema as REQUIRED broke `loadCurated` immediately: 25 manifests
are already committed without it, and the builder's own rule is that a released
version's content is immutable — a same-day change ships under a new version
name rather than rewriting an old one. So the field is `.optional()`, like
`shrinkage_acknowledgments`. To stop that optionality becoming a licence to
skip it, `build.test.ts` asserts a NEW build always writes it, so "absent"
means "built before 9.1010.0" and never "a build that skipped it".

**The fetch script is deliberately not built.** This spec's rule is that no
mandated text enters from a secondary source, and each passage here was read at
an official one by a person — the eCFR versioner for the two FTC notices. An
automatic fetcher would make the table's provenance a matter of whatever a URL
served that week. The scheduled re-read is `npm run authority:drift` (9.1007.0),
which reports a wording change for a person to act on rather than silently
replacing the text.

**Migrating the two Texas literals is still declined**, for the measured reason
in the 9.1004.0 note: the privacy pack already matches them case-sensitively
and reports an altered rendering, so `TEXT-001` would report the same defect a
second time — the thing task 8 exists to prevent. They gained the provenance
that migration was really worth in 9.1004.0.

## Progress — task 10's three clauses, settled where they can be

**"CHANGELOG lists every corpus finding the change adds" — the number is
ZERO, and it is held by a test rather than asserted.** Across all 363
specimens, `TEXT-001`, `TEXT-002` and `TEXT-003` together draw nothing:
`mandated-text-corpus.test.ts`'s sweep fails on any hit, and it ran green in
the 9.1010.0 gate. Every golden regenerated semantically identical at each
release in this change's history (345 files checked by parsing both sides and
stripping the version stamp), including after the anchor-path fix at 9.1005.0
that made `TEXT-001` able to see a truncated notice. So there is no corpus
finding to list: the pack fires only on a document that actually carries a
mandated notice, and no specimen does.

**"Regenerate goldens once" — done at each release**, with the semantic check
above rather than a glance at the diff (the goldens are minified single-line
JSON, so `git diff` shows the whole object and tells a reader nothing).

**"Land with a scheduled DKB rebuild" belongs to the scheduled job, and that
is the task's own wording.** It is not a dodge, and the reason is mechanical:
`tools/dkb/resolve.ts` resolves the active artifact as *the newest version
directory in `dkb/dist/`*. Committing a hand-built version here would
immediately change which DKB the engine reads, stamp a new version into every
run, churn every golden, and bypass `dkb-rebuild.yml`'s own regression and
shrinkage gates — the machinery that decides commit-versus-PR precisely so a
DKB change reaches a person.

What this session made sure of instead is that the scheduled job will carry the
table when it next runs:

- `runBuild` writes `dkb-mandated-texts.json` and references it in the manifest
  with its entry count and SHA-256 (verified by building to a scratch version
  and reading the file, which was then deleted rather than committed).
- `build.test.ts` asserts a NEW build always writes it, so the optional
  manifest field cannot silently go missing.
- `assertMandatedTextsUsable` runs inside the build, so the scheduled job fails
  rather than shipping a passage whose provenance cannot be shown.
- `dkb-rebuild.yml` also runs `npm run authority:drift`, so the same job that
  lands the table re-reads its passages at their official sources.

## Progress — 9.1012.0 (`w:caps`, and the note that said it wasn't needed)

🚨 **The deferral's reason was half false, and the false half hid a real false
positive.** The note read: "`w:caps` is not read, and no row needs capitals."
The first clause was true. The second was wrong in a way that mattered: no
MANDATED TEXT row needs capitals, but **`TEXT-003` does**, and `TEXT-003` is not
a mandated-text row. U.C.C. § 1-201(b)(10) counts capitals as one way for a
warranty disclaimer to be conspicuous, and the rule was reading the TEXT's own
case.

A Word user who applies All Caps formatting — the ordinary way to do it —
leaves the stored text mixed case, and mammoth drops `w:caps`, so the ingest
never saw it either. **Measured: the same DOCX fired `TEXT-003` identically
with and without `w:caps` on the disclaimer**, so a disclaimer Word displays
entirely in capitals was reported as "in plain body type" — a false statement
about the document.

`src/ingest/docx-caps.ts` reads the property from `word/document.xml` directly,
the way `docx-sizes.ts` reads `w:sz`, and attaches
`Paragraph.displayed_caps`; `TEXT-003` now treats it as capitals.

🚨 **A case bug in my own first version, and the module returned an EMPTY SET
because of it.** The pattern was `/<w:(?:small)?Caps\b/` — which matches
`w:smallCaps` and **not** `w:caps`, because OOXML spells the commoner of the two
in lowercase. The probe showed `capsParagraphs() → []` on a document that
plainly had the formatting. Both spellings are now named explicitly and a test
pins each. This is the class `2026-08-31-goal-loop-s24` is about: a pattern
written in one case does not apply to half its inputs.

Scope stated rather than implied: a run's own `w:rPr` and the paragraph's
`w:pPr/w:rPr` are read; a character or paragraph STYLE that sets caps without
the run saying so is not followed. `w:sz` needed that chain because most text
inherits its size, whereas `w:caps` is nearly always applied directly — and a
missed marker leaves the previous behaviour, which is the safe direction: it can
only make the rule speak, never silence it wrongly.

Also deliberate: a PARTLY caps-formatted paragraph does not count as capitals.
A single caps word in a mixed-case clause is not what § 1-201(b)(10) describes,
and treating it as capitals would silence `TEXT-003` on a disclaimer that is not
conspicuous at all. Tested.

## Closing tasks 1, 2 and 4 — every item built or declined with a written reason

These three were `[~]` because part of each was DECLINED, not because work
remained. Each decline is recorded above with the evidence that produced it, so
leaving them open implies a developer has something to do, and none does.
Verified before flipping:

**Task 1 — every seed authority read or decided.** 16 C.F.R. § 433.2 and
§ 429.1 read at eCFR (9.982.0, 9.1007.0 re-verifies them on the scheduled
path). Tex. Bus. & Com. Code § 541.102 read at statutes.capitol.texas.gov on
2026-11-23 and unchanged, with provenance added where it lives (9.1004.0).
Cal. Civ. Code § 1542 **read** at leginfo on 2026-11-23 — the recorded 403 was
a fetch limitation, not the statute's — and then declined as a mandated text:
it prescribes no wording, and its 2018 amendment is expressly declaratory of
existing law. 18 U.S.C. § 1833(b)(3) declined on examination: it requires
notice OF an immunity and permits a cross-reference to a policy, so it
prescribes no passage.

**Task 2 — schema, gate and validation test built** (9.1010.0, 15 defect cases).
The fetch script is declined because this spec forbids a secondary source and
an auto-fetcher would make the table's provenance whatever a URL served that
week; `authority:drift` is the scheduled re-read instead. The Texas migration
is declined because the privacy pack already reports an altered rendering, so
`TEXT-001` would be a second finding for one defect — task 8's rule.

**Task 4 — the factory's shapes built, verified in the code just now:**
`TEXT-001` is the altered shape with the word-diff redline; `TEXT-002` IS the
`TEXT-FORM-<row>` shape, reading bold per run and point size from both DOCX and
PDF; and the gating is stronger than the "family list or registered assertion"
the task asked for — both rules are **presence-conditioned**, firing only where
the document already carries the notice, so they cannot speak about a document
the authority does not reach. The superseded shape is declined because no row
has a substantive version change, and a detector no row can reach is dead code.

**What is left on this change is task 10's landing**, which belongs to the
scheduled DKB rebuild by design. Nothing there is a developer's to do.
